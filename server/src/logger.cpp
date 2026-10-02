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

static void writeAll(int fd, const char* p, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t w = ::write(fd, p + off, n - off);
        if (w < 0) { if (errno == EINTR) continue; break; }
        off += size_t(w);
    }
}

static const char* tagColor(const std::string& t) {
    if (t == "INFO") return "36";
    if (t == "WARN") return "33";
    if (t == "ERROR" || t == "DENIED") return "31";
    if (t == "CLIENT") return "32";
    if (t == "UPLOAD" || t == "DOWNLOAD") return "34";
    return "35";
}

void Logger::writeLine(const char* tag, LogLevel level, const char* rawMsg, bool console) {
    char msg[2048];
    std::snprintf(msg, sizeof msg, "%s", rawMsg);
    // strip control characters so untrusted input cannot forge log lines
    for (char* p = msg; *p; ++p)
        if ((unsigned char)*p < 0x20 && *p != '\t') *p = '?';

    time_t now = time(nullptr);
    struct tm tmv;
    localtime_r(&now, &tmv);
    char ts[32];
    std::strftime(ts, sizeof ts, "%Y-%m-%d %H:%M:%S", &tmv);
    char line[2200];
    int n = std::snprintf(line, sizeof line, "%s [%-5s] %s\n", ts, tag, msg);
    if (n < 0) return;
    if (size_t(n) >= sizeof line) n = int(sizeof line) - 1;

    std::lock_guard<std::mutex> lk(mu_);
    if (fd_ >= 0) writeAll(fd_, line, size_t(n));
    if (console && console_) {
        FILE* out = (level >= LogLevel::WARN) ? stderr : stdout;
        if (isatty(fileno(out))) std::fprintf(out, "\033[%sm[%s]\033[0m %s\n", tagColor(tag), tag, msg);
        else std::fprintf(out, "[%s] %s\n", tag, msg);
        std::fflush(out);
    }
}

void Logger::log(LogLevel level, const char* fmt, ...) {
    if (level < level_) return;
    char msg[2048];
    va_list ap;
    va_start(ap, fmt);
    std::vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);
    static const char* names[] = {"DEBUG", "INFO", "WARN", "ERROR"};
    writeLine(names[int(level)], level, msg, true);
}

void Logger::event(const char* tag, const char* fmt, ...) {
    char msg[2048];
    va_list ap;
    va_start(ap, fmt);
    std::vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);
    writeLine(tag, LogLevel::INFO, msg, true);
}

void Logger::fileOnly(const char* fmt, ...) {
    char msg[2048];
    va_list ap;
    va_start(ap, fmt);
    std::vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);
    writeLine("INFO", LogLevel::INFO, msg, false);
}

void Logger::banner(const std::string& text) {
    std::lock_guard<std::mutex> lk(mu_);
    if (fd_ >= 0) writeAll(fd_, text.data(), text.size());
    if (console_) { std::fwrite(text.data(), 1, text.size(), stdout); std::fflush(stdout); }
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
    Logger::instance().fileOnly("AUDIT user=%s action=%s target=%s result=%s from=%s %s", username.c_str(),
                                action.c_str(), target.c_str(), result.c_str(), clientAddr.c_str(), detail.c_str());
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
