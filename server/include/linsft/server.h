// Server composition: Services (all managers), ConnectionManager (accept loop + thread per client)
// and LinSFTServer (lifecycle facade used by main() and by the test-suite).
#pragma once
#include <atomic>
#include <ctime>
#include <list>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#include "linsft/auth.h"
#include "linsft/database.h"
#include "linsft/file_manager.h"
#include "linsft/logger.h"
#include "linsft/system_monitor.h"
#include "linsft/transfer_manager.h"

namespace linsft {

struct ServerConfig {
    std::string bindAddress = "127.0.0.1";
    uint16_t port = 5000;
    std::string storageDir = "server_storage";
    std::string dbPath = "database/file_sharing.db";
    std::string logPath = "logs/server.log";
    size_t maxClients = 64;
    uint64_t maxFileSize = 512ULL * 1024 * 1024;
    int sessionTtlSeconds = 1800;
    uint32_t pbkdf2Iterations = 100000;
    int idleTimeoutSeconds = 300;
    bool logToConsole = true;

    // key = value lines; '#' comments. Returns false with err on unreadable file / bad value.
    bool loadFile(const std::string& path, std::string& err);
};

struct Services {
    explicit Services(const ServerConfig& c)
        : cfg(c), audit(db), auth(db, c.pbkdf2Iterations, c.sessionTtlSeconds),
          files(db, c.storageDir), transfers(db, files, stats, c.maxFileSize),
          sysmon(c.storageDir, stats, long(time(nullptr))) {}
    ServerConfig cfg;
    DatabaseManager db;
    AuditLogger audit;
    AuthenticationManager auth;
    FileManager files;
    ServerStats stats;
    TransferManager transfers;
    SystemMonitor sysmon;

    bool init(std::string& err);  // log, database, storage, stale transfer recovery
};

class ConnectionManager {
public:
    explicit ConnectionManager(Services& s) : svc_(s) {}
    ~ConnectionManager();
    bool listen(const std::string& addr, uint16_t port, std::string& err);
    uint16_t port() const { return port_; }
    void run();   // blocks in the accept loop until stop()
    void stop();  // safe to call from another thread
private:
    struct Client {
        int fd = -1;
        std::thread th;
        std::atomic<bool> done{false};
    };
    void reap(bool all);
    Services& svc_;
    int listenFd_ = -1;
    uint16_t port_ = 0;
    std::atomic<bool> running_{false};
    std::mutex mu_;
    std::list<std::unique_ptr<Client>> clients_;
};

class LinSFTServer {
public:
    explicit LinSFTServer(const ServerConfig& cfg) : svc_(cfg), conns_(svc_) {}
    ~LinSFTServer() { stop(); }
    bool start(std::string& err);  // init services, bind, start accept thread
    void stop();                   // graceful: stop accepting, wake + join all client threads
    uint16_t port() const { return conns_.port(); }
    Services& services() { return svc_; }
private:
    Services svc_;
    ConnectionManager conns_;
    std::thread acceptor_;
    bool started_ = false;
};

}  // namespace linsft
