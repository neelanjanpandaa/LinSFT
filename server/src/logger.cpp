#include "linsft/logger.h"

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <ctime>

namespace linsft {

Logger& Logger::instance() {
    static Logger l;
    return l;
}

bool Logger::open(const std::string& path, std::string& err) {
    std::lock_guard<std::mutex> lk(mu_);
    if (fd_ >= 0) ::close(fd_);
    fd_ = ::open(path.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0640);
    if (fd_ < 0) { err = std::string("open log '") + path + "': " + std::strerror(errno); return false; }
    return true;
}

void Logger::close() {
    std::lock_guard<std::mutex> lk(mu_);
    if (fd_ >= 0) { ::close(fd_); fd_ = -1; }
}

void Logger::log(LogLevel level, const char* fmt, ...) {
    if (level < level_) return;
    char msg[2048];
    va_list ap;
    va_start(ap, fmt);
    std::vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);
    // strip control characters so untrusted input cannot forge log lines
    for (char* p = msg; *p; ++p)
        if ((unsigned char)*p < 0x20 && *p != '\t') *p = '?';

    static const char* names[] = {"DEBUG", "INFO ", "WARN ", "ERROR"};
    time_t now = time(nullptr);
    struct tm tmv;
    localtime_r(&now, &tmv);
    char ts[32];
    std::strftime(ts, sizeof ts, "%Y-%m-%d %H:%M:%S", &tmv);
    char line[2200];
    int n = std::snprintf(line, sizeof line, "%s [%s] %s\n", ts, names[int(level)], msg);
    if (n < 0) return;
    if (size_t(n) >= sizeof line) n = int(sizeof line) - 1;

    std::lock_guard<std::mutex> lk(mu_);
    if (fd_ >= 0) {
        size_t off = 0;
        while (off < size_t(n)) {
            ssize_t w = ::write(fd_, line + off, size_t(n) - off);
            if (w < 0) { if (errno == EINTR) continue; break; }
            off += size_t(w);
        }
    }
    if (console_) {
        FILE* out = (level >= LogLevel::WARN) ? stderr : stdout;
        std::fwrite(line, 1, size_t(n), out);
        std::fflush(out);
    }
}

void AuditLogger::record(int64_t userId, const std::string& username, const std::string& action,
                         const std::string& target, const std::string& result,
                         const std::string& clientAddr, const std::string& detail) {
    try {
        db_.exec("INSERT INTO audit_logs(ts,user_id,username,action,target,result,client_addr,detail) "
                 "VALUES(?,?,?,?,?,?,?,?)",
                 {int64_t(time(nullptr)), userId, username, action, target, result, clientAddr, detail});
    } catch (const std::exception& e) {
        LOG_ERROR("audit write failed: %s", e.what());
    }
    LOG_INFO("AUDIT user=%s action=%s target=%s result=%s from=%s %s", username.c_str(), action.c_str(),
             target.c_str(), result.c_str(), clientAddr.c_str(), detail.c_str());
}

std::vector<AuditEntry> AuditLogger::recent(size_t limit) {
    std::vector<AuditEntry> out;
    auto rows = db_.query("SELECT id,ts,user_id,username,action,target,result,client_addr,detail "
                          "FROM audit_logs ORDER BY id DESC LIMIT ?",
                          {int64_t(limit)});
    for (auto& r : rows) {
        AuditEntry e;
        e.id = DatabaseManager::asInt(r[0]); e.ts = DatabaseManager::asInt(r[1]);
        e.userId = DatabaseManager::asInt(r[2]); e.username = DatabaseManager::asStr(r[3]);
        e.action = DatabaseManager::asStr(r[4]); e.target = DatabaseManager::asStr(r[5]);
        e.result = DatabaseManager::asStr(r[6]); e.clientAddr = DatabaseManager::asStr(r[7]);
        e.detail = DatabaseManager::asStr(r[8]);
        out.push_back(std::move(e));
    }
    return out;
}

}  // namespace linsft
