#include "linsft/models.h"

#include <sys/stat.h>

#include <cstdio>
#include <ctime>

namespace linsft {

void write(Writer& w, const FileEntry& e) {
    w.i64(e.id).str(e.path).str(e.name).boolean(e.isDir).u64(e.size).i64(e.ownerId).str(e.owner)
        .str(e.sha256).boolean(e.shared).i64(e.created).i64(e.modified).u32(e.mode);
}
FileEntry readFileEntry(Reader& r) {
    FileEntry e;
    e.id = r.i64(); e.path = r.str(); e.name = r.str(); e.isDir = r.boolean(); e.size = r.u64();
    e.ownerId = r.i64(); e.owner = r.str(); e.sha256 = r.str(); e.shared = r.boolean();
    e.created = r.i64(); e.modified = r.i64(); e.mode = r.u32();
    return e;
}
void write(Writer& w, const UserEntry& e) {
    w.i64(e.id).str(e.username).str(e.role).i64(e.created).i64(e.lastLogin);
}
UserEntry readUserEntry(Reader& r) {
    UserEntry e;
    e.id = r.i64(); e.username = r.str(); e.role = r.str(); e.created = r.i64(); e.lastLogin = r.i64();
    return e;
}
void write(Writer& w, const TransferEntry& e) {
    w.i64(e.id).i64(e.userId).str(e.username).str(e.direction).str(e.path).u64(e.size)
        .str(e.sha256).str(e.status).str(e.detail).str(e.clientAddr).i64(e.started).i64(e.finished);
}
TransferEntry readTransferEntry(Reader& r) {
    TransferEntry e;
    e.id = r.i64(); e.userId = r.i64(); e.username = r.str(); e.direction = r.str(); e.path = r.str();
    e.size = r.u64(); e.sha256 = r.str(); e.status = r.str(); e.detail = r.str(); e.clientAddr = r.str();
    e.started = r.i64(); e.finished = r.i64();
    return e;
}
void write(Writer& w, const AuditEntry& e) {
    w.i64(e.id).i64(e.ts).i64(e.userId).str(e.username).str(e.action).str(e.target).str(e.result)
        .str(e.clientAddr).str(e.detail);
}
AuditEntry readAuditEntry(Reader& r) {
    AuditEntry e;
    e.id = r.i64(); e.ts = r.i64(); e.userId = r.i64(); e.username = r.str(); e.action = r.str();
    e.target = r.str(); e.result = r.str(); e.clientAddr = r.str(); e.detail = r.str();
    return e;
}

void writeKeyValues(Writer& w, const KeyValues& kv) {
    w.u32(uint32_t(kv.size()));
    for (auto& p : kv) w.str(p.first).str(p.second);
}
KeyValues readKeyValues(Reader& r) {
    uint32_t n = r.u32();
    if (n > 10000) throw ProtocolError("too many entries");
    KeyValues kv;
    for (uint32_t i = 0; i < n; ++i) {
        std::string k = r.str();
        std::string v = r.str(65536);
        kv.emplace_back(std::move(k), std::move(v));
    }
    return kv;
}

std::string formatTime(int64_t t) {
    if (t <= 0) return "-";
    time_t tt = time_t(t);
    struct tm tmv;
    localtime_r(&tt, &tmv);
    char buf[32];
    std::strftime(buf, sizeof buf, "%Y-%m-%d %H:%M:%S", &tmv);
    return buf;
}

std::string humanSize(uint64_t b) {
    const char* units[] = {"B", "KiB", "MiB", "GiB", "TiB"};
    double v = double(b);
    int u = 0;
    while (v >= 1024.0 && u < 4) { v /= 1024.0; ++u; }
    char buf[32];
    if (u == 0) std::snprintf(buf, sizeof buf, "%llu B", (unsigned long long)b);
    else std::snprintf(buf, sizeof buf, "%.1f %s", v, units[u]);
    return buf;
}

}  // namespace linsft

namespace linsft {

std::string modeString(uint32_t m) {
    std::string s(10, '-');
    if (S_ISDIR(m)) s[0] = 'd';
    else if (S_ISLNK(m)) s[0] = 'l';
    const char* rwx = "rwxrwxrwx";
    for (int i = 0; i < 9; ++i)
        if (m & (1u << (8 - i))) s[size_t(i) + 1] = rwx[i];
    return s;
}

std::string modeOctal(uint32_t m) {
    char buf[8];
    std::snprintf(buf, sizeof buf, "%04o", m & 07777);
    return buf;
}

}  // namespace linsft
