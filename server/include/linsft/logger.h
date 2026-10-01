// Thread-safe server log (POSIX open/write with O_APPEND) and DB-backed audit trail.
#pragma once
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

#include "linsft/database.h"
#include "linsft/models.h"

namespace linsft {

enum class LogLevel { DEBUG = 0, INFO = 1, WARN = 2, ERROR = 3 };

class Logger {
public:
    static Logger& instance();
    bool open(const std::string& path, std::string& err);
    void close();
    void setConsole(bool on) { console_ = on; }
    void setLevel(LogLevel l) { level_ = l; }
    void log(LogLevel level, const char* fmt, ...) __attribute__((format(printf, 3, 4)));
private:
    Logger() = default;
    std::mutex mu_;
    int fd_ = -1;
    bool console_ = true;
    LogLevel level_ = LogLevel::INFO;
};

#define LOG_DEBUG(...) ::linsft::Logger::instance().log(::linsft::LogLevel::DEBUG, __VA_ARGS__)
#define LOG_INFO(...) ::linsft::Logger::instance().log(::linsft::LogLevel::INFO, __VA_ARGS__)
#define LOG_WARN(...) ::linsft::Logger::instance().log(::linsft::LogLevel::WARN, __VA_ARGS__)
#define LOG_ERROR(...) ::linsft::Logger::instance().log(::linsft::LogLevel::ERROR, __VA_ARGS__)

// Persists security relevant events in audit_logs and mirrors them to the server log.
class AuditLogger {
public:
    explicit AuditLogger(DatabaseManager& db) : db_(db) {}
    void record(int64_t userId, const std::string& username, const std::string& action,
                const std::string& target, const std::string& result, const std::string& clientAddr,
                const std::string& detail = "");
    std::vector<AuditEntry> recent(size_t limit);
private:
    DatabaseManager& db_;
};

}  // namespace linsft
