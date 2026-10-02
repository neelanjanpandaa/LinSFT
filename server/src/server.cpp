#include "linsft/server.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <fstream>

#include "linsft/connection_handler.h"

namespace linsft {

// ---- config -------------------------------------------------------------
static std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n"), b = s.find_last_not_of(" \t\r\n");
    return a == std::string::npos ? "" : s.substr(a, b - a + 1);
}

bool ServerConfig::loadFile(const std::string& path, std::string& err) {
    std::ifstream f(path);
    if (!f) { err = "cannot read config file " + path; return false; }
    std::string line;
    int ln = 0;
    while (std::getline(f, line)) {
        ++ln;
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        size_t eq = line.find('=');
        if (eq == std::string::npos) { err = path + ":" + std::to_string(ln) + ": expected key = value"; return false; }
        std::string k = trim(line.substr(0, eq)), v = line.substr(eq + 1);
        size_t hash = v.find(" #");  // inline comment: whitespace followed by '#'
        size_t tabHash = v.find("\t#");
        if (tabHash != std::string::npos && (hash == std::string::npos || tabHash < hash)) hash = tabHash;
        if (hash != std::string::npos) v.erase(hash);
        v = trim(v);
        try {
            if (k == "bind_address") bindAddress = v;
            else if (k == "port") { long p = std::stol(v); if (p < 0 || p > 65535) throw std::out_of_range("port"); port = uint16_t(p); }
            else if (k == "storage_dir") storageDir = v;
            else if (k == "db_path") dbPath = v;
            else if (k == "log_path") logPath = v;
            else if (k == "max_clients") maxClients = size_t(std::stoul(v));
            else if (k == "max_file_size") maxFileSize = std::stoull(v);
            else if (k == "session_ttl_seconds") sessionTtlSeconds = std::stoi(v);
            else if (k == "pbkdf2_iterations") { pbkdf2Iterations = uint32_t(std::stoul(v)); if (pbkdf2Iterations < 1000) throw std::out_of_range("pbkdf2_iterations"); }
            else if (k == "idle_timeout_seconds") idleTimeoutSeconds = std::stoi(v);
            else { err = path + ":" + std::to_string(ln) + ": unknown key '" + k + "'"; return false; }
        } catch (const std::exception&) {
            err = path + ":" + std::to_string(ln) + ": invalid value for '" + k + "'";
            return false;
        }
    }
    return true;
}

// ---- services -----------------------------------------------------------
static void ensureParentDir(const std::string& file) {
    size_t p = file.find_last_of('/');
    if (p != std::string::npos && p > 0) ::mkdir(file.substr(0, p).c_str(), 0750);
}

bool Services::init(std::string& err) {
    ensureParentDir(cfg.logPath);
    ensureParentDir(cfg.dbPath);
    Logger::instance().setConsole(cfg.logToConsole);
    if (!Logger::instance().open(cfg.logPath, err)) return false;
    if (!db.open(cfg.dbPath, err)) return false;
    if (!files.init(err)) return false;
    files.ensureDefaultLayout();
    transfers.recoverStale();
    return true;
}

// ---- connection manager -------------------------------------------------
ConnectionManager::~ConnectionManager() {
    stop();
    if (listenFd_ >= 0) { ::close(listenFd_); listenFd_ = -1; }
}

bool ConnectionManager::listen(const std::string& addr, uint16_t port, std::string& err) {
    int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) { err = std::string("socket: ") + std::strerror(errno); return false; }
    int one = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    if (::inet_pton(AF_INET, addr.c_str(), &sa.sin_addr) != 1) { err = "invalid bind address: " + addr; ::close(fd); return false; }
    if (::bind(fd, reinterpret_cast<sockaddr*>(&sa), sizeof sa) != 0) {
        err = "bind " + addr + ":" + std::to_string(port) + ": " + std::strerror(errno);
        ::close(fd);
        return false;
    }
    if (::listen(fd, 128) != 0) { err = std::string("listen: ") + std::strerror(errno); ::close(fd); return false; }
    socklen_t sl = sizeof sa;
    ::getsockname(fd, reinterpret_cast<sockaddr*>(&sa), &sl);
    port_ = ntohs(sa.sin_port);
    listenFd_ = fd;
    running_ = true;  // set before the accept thread starts so an early stop() is not lost
    return true;
}

void ConnectionManager::reap(bool all) {
    std::lock_guard<std::mutex> lk(mu_);
    for (auto it = clients_.begin(); it != clients_.end();) {
        Client& c = **it;
        if (all || c.done.load()) {
            if (all) ::shutdown(c.fd, SHUT_RDWR);  // wakes a thread blocked in recv()
            if (c.th.joinable()) c.th.join();
            ::close(c.fd);
            it = clients_.erase(it);
        } else {
            ++it;
        }
    }
}

void ConnectionManager::run() {
    Logger::instance().fileOnly("listening on port %u", unsigned(port_));
    while (running_) {
        pollfd pfd{listenFd_, POLLIN, 0};
        int pr = ::poll(&pfd, 1, 200);  // short timeout so stop() is noticed promptly
        reap(false);
        if (pr < 0) { if (errno == EINTR) continue; LOG_ERROR("poll: %s", std::strerror(errno)); break; }
        if (pr == 0 || !(pfd.revents & POLLIN)) continue;
        sockaddr_in ca{};
        socklen_t cl = sizeof ca;
        int cfd = ::accept4(listenFd_, reinterpret_cast<sockaddr*>(&ca), &cl, SOCK_CLOEXEC);
        if (cfd < 0) {
            if (errno == EINTR || errno == ECONNABORTED || errno == EAGAIN) continue;
            LOG_ERROR("accept: %s", std::strerror(errno));
            if (errno == EMFILE || errno == ENFILE) { ::usleep(100000); continue; }
            break;
        }
        char ip[INET_ADDRSTRLEN] = "?";
        ::inet_ntop(AF_INET, &ca.sin_addr, ip, sizeof ip);
        std::string addr = std::string(ip) + ":" + std::to_string(ntohs(ca.sin_port));

        size_t n;
        { std::lock_guard<std::mutex> lk(mu_); n = clients_.size(); }
        if (n >= svc_.cfg.maxClients) {
            LOG_WARN("rejecting %s: too many clients (%zu)", addr.c_str(), n);
            std::string e;
            sendMessage(cfd, makeResponse(0, 0, Status::BUSY, "server is at capacity"), e);
            ::close(cfd);
            continue;
        }
        int one = 1;
        ::setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        timeval tv{svc_.cfg.idleTimeoutSeconds, 0};
        ::setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

        auto client = std::make_unique<Client>();
        client->fd = cfd;
        Client* raw = client.get();
        try {
            client->th = std::thread([this, raw, cfd, addr]() {
                try {
                    ConnectionHandler h(svc_, cfd, addr);
                    h.run();
                } catch (const std::exception& e) {
                    LOG_ERROR("client thread for %s crashed: %s", addr.c_str(), e.what());
                } catch (...) {
                    LOG_ERROR("client thread for %s crashed (unknown exception)", addr.c_str());
                }
                raw->done = true;
            });
        } catch (const std::system_error& e) {
            LOG_ERROR("cannot start thread for %s: %s", addr.c_str(), e.what());
            ::close(cfd);
            continue;
        }
        std::lock_guard<std::mutex> lk(mu_);
        clients_.push_back(std::move(client));
    }
    LOG_INFO("accept loop stopped; closing %zu client connection(s)", clients_.size());
    reap(true);
    if (listenFd_ >= 0) { ::close(listenFd_); listenFd_ = -1; }
    running_ = false;
}

void ConnectionManager::stop() { running_ = false; }

// ---- facade -------------------------------------------------------------
bool LinSFTServer::start(std::string& err) {
    if (started_) return true;
    if (!svc_.init(err)) return false;
    if (!conns_.listen(svc_.cfg.bindAddress, svc_.cfg.port, err)) return false;
    started_ = true;
    acceptor_ = std::thread([this]() { conns_.run(); });
    return true;
}

void LinSFTServer::stop() {
    if (!started_) return;
    conns_.stop();
    if (acceptor_.joinable()) acceptor_.join();
    started_ = false;
    LOG_INFO("server stopped");
}

}  // namespace linsft
