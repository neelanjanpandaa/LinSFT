// network-file-server: LinSFT TCP server + administration commands.
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>

#include "linsft/crypto.h"
#include "linsft/pathutil.h"
#include "linsft/server.h"

using namespace linsft;

static volatile sig_atomic_t g_stop = 0;
static void onSignal(int) { g_stop = 1; }

static void usage() {
    std::puts(
        "LinSFT server\n\n"
        "Usage: network-file-server [PORT] [options]      (also installed as ./file_server)\n"
        "  PORT                 listening port (default 5000), e.g.  ./file_server 5000\n"
        "  --config FILE        configuration file (default: config/server.conf if present)\n"
        "  --port N             override listening port\n"
        "  --bind ADDR          override bind address (default 127.0.0.1)\n"
        "  --quiet              do not echo the log to the console\n"
        "  --init-admin USER    create (or reset the password of) an ADMIN account, then exit.\n"
        "                       Password is read from $LINSFT_ADMIN_PASSWORD or prompted.\n"
        "  --seed-demo          create demo accounts (admin, faculty1, student1) with random\n"
        "                       passwords + a shared demo file, write config/demo-credentials.txt, exit\n"
        "  --version, --help\n");
}

static bool readPassword(const std::string& label, std::string& out) {
    if (const char* env = std::getenv("LINSFT_ADMIN_PASSWORD")) { out = env; return true; }
    bool tty = isatty(STDIN_FILENO);
    termios oldt{};
    if (tty) {
        tcgetattr(STDIN_FILENO, &oldt);
        termios nt = oldt;
        nt.c_lflag &= ~tcflag_t(ECHO);
        tcsetattr(STDIN_FILENO, TCSANOW, &nt);
    }
    std::cerr << label << ": " << std::flush;
    bool ok = bool(std::getline(std::cin, out));
    if (tty) { tcsetattr(STDIN_FILENO, TCSANOW, &oldt); std::cerr << "\n"; }
    return ok;
}

static std::string randomPassword() {
    static const char alphabet[] = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    std::string p;
    uint8_t b[16];
    randomBytes(b, sizeof b);
    for (uint8_t c : b) p += alphabet[c % (sizeof(alphabet) - 1)];
    return p;
}

static int initAdmin(Services& svc, const std::string& user) {
    std::string pass;
    if (!readPassword("New password for " + user, pass)) { std::cerr << "no password supplied\n"; return 1; }
    if (!std::getenv("LINSFT_ADMIN_PASSWORD") && isatty(STDIN_FILENO)) {
        std::string again;
        if (!readPassword("Repeat password", again) || again != pass) { std::cerr << "passwords do not match\n"; return 1; }
    }
    std::string msg;
    Status st = svc.auth.createOrUpdateUser(user, pass, Role::ADMIN, msg);
    if (st != Status::OK) { std::cerr << "failed: " << msg << "\n"; return 1; }
    std::cout << "Admin account '" << user << "' " << msg << ".\n";
    return 0;
}

static int seedDemo(Services& svc) {
    struct Acct { const char* name; Role role; std::string pw; };
    std::vector<Acct> accts = {{"admin", Role::ADMIN, randomPassword()},
                               {"faculty1", Role::FACULTY, randomPassword()},
                               {"student1", Role::STUDENT, randomPassword()}};
    for (auto& a : accts) {
        std::string msg;
        if (svc.auth.createOrUpdateUser(a.name, a.pw, a.role, msg) != Status::OK) {
            std::cerr << "failed to create " << a.name << ": " << msg << "\n";
            return 1;
        }
    }
    // demo content: a shared welcome file in /public owned by admin (default layout already exists)
    int64_t adminId = DatabaseManager::asInt(svc.db.query("SELECT id FROM users WHERE username='admin'")[0][0]);
    if (!svc.files.find("/public/WELCOME.txt")) {
        const std::string text =
            "Welcome to LinSFT!\n\nThis shared demo file was created by 'network-file-server --seed-demo'.\n"
            "Try: download it, view its info (SHA-256), upload your own files, search, rename, delete.\n";
        std::string tmp = svc.files.tmpDir() + "/up-seed-" + randomHex(6);
        int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0640);
        if (fd >= 0) {
            bool ok = ::write(fd, text.data(), text.size()) == ssize_t(text.size());
            ::close(fd);
            if (ok) svc.files.commitUpload(tmp, "/public/WELCOME.txt", adminId, text.size(),
                                          Sha256::hashHex(text), true, true);
            else ::unlink(tmp.c_str());
        }
    }
    const char* credPath = "config/demo-credentials.txt";
    int fd = ::open(credPath, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    std::string body = "# LinSFT demo credentials (generated; keep private, do not commit)\n";
    for (auto& a : accts) body += std::string(a.name) + " " + roleName(a.role) + " " + a.pw + "\n";
    if (fd >= 0) { if (::write(fd, body.data(), body.size()) < 0) {} ::close(fd); }
    std::cout << "Demo accounts ready:\n";
    for (auto& a : accts) std::cout << "  " << a.name << "  (" << roleName(a.role) << ")  password: " << a.pw << "\n";
    if (fd >= 0) std::cout << "Saved to " << credPath << " (mode 0600).\n";
    return 0;
}

int main(int argc, char** argv) {
    ServerConfig cfg;
    std::string configPath, err, initAdminUser;
    bool seed = false, quiet = false;
    int portOverride = -1;
    std::string bindOverride;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&](const char* what) -> std::string {
            if (i + 1 >= argc) { std::cerr << "missing value for " << what << "\n"; std::exit(2); }
            return argv[++i];
        };
        if (a == "--help" || a == "-h") { usage(); return 0; }
        else if (a == "--version") { std::puts("LinSFT server 1.0.0"); return 0; }
        else if (a == "--config") configPath = next("--config");
        else if (a == "--port") portOverride = std::atoi(next("--port").c_str());
        else if (a == "--bind") bindOverride = next("--bind");
        else if (a == "--quiet") quiet = true;
        else if (a == "--init-admin") initAdminUser = next("--init-admin");
        else if (a == "--seed-demo") seed = true;
        else if (!a.empty() && a.find_first_not_of("0123456789") == std::string::npos) portOverride = std::atoi(a.c_str());  // positional PORT
        else { std::cerr << "unknown option: " << a << "\n"; usage(); return 2; }
    }
    if (configPath.empty()) {
        struct stat st;
        if (::stat("config/server.conf", &st) == 0) configPath = "config/server.conf";
    }
    if (!configPath.empty() && !cfg.loadFile(configPath, err)) { std::cerr << "config error: " << err << "\n"; return 2; }
    if (portOverride >= 0) {
        if (portOverride > 65535) { std::cerr << "invalid port\n"; return 2; }
        cfg.port = uint16_t(portOverride);
    }
    if (!bindOverride.empty()) cfg.bindAddress = bindOverride;
    if (quiet) cfg.logToConsole = false;

    // SIGINT/SIGTERM request a graceful shutdown; SIGPIPE must never kill the server.
    struct sigaction sa{};
    sa.sa_handler = onSignal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    signal(SIGPIPE, SIG_IGN);

    if (!initAdminUser.empty() || seed) {
        cfg.logToConsole = false;
        Services svc(cfg);
        if (!svc.init(err)) { std::cerr << "init failed: " << err << "\n"; return 1; }
        return seed ? seedDemo(svc) : initAdmin(svc, initAdminUser);
    }

    LinSFTServer server(cfg);
    if (!server.start(err)) { std::cerr << "server start failed: " << err << "\n"; return 1; }
    {
        char b[640];
        const char* bar = "==================================================";
        std::snprintf(b, sizeof b,
                      "%s\n          Network File Sharing Server\n%s\n"
                      "Port     : %u\nStorage  : ./%s\nDatabase : %s\nStatus   : RUNNING\n%s\n",
                      bar, bar, unsigned(server.port()), cfg.storageDir.c_str(), cfg.dbPath.c_str(), bar);
        Logger::instance().banner(b);
    }
    LOG_INFO("Server started. Waiting for clients... (Ctrl+C to stop)");
    struct timespec ts{0, 100 * 1000 * 1000};
    while (!g_stop) nanosleep(&ts, nullptr);
    LOG_INFO("signal received - shutting down gracefully");
    server.stop();
    Logger::instance().close();
    return 0;
}
