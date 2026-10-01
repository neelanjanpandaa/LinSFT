// Wire models shared by client and server.
#pragma once
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "linsft/protocol.h"

namespace linsft {

struct FileEntry {
    int64_t id = 0;
    std::string path, name;
    bool isDir = false;
    uint64_t size = 0;
    int64_t ownerId = 0;
    std::string owner;
    std::string sha256;
    bool shared = false;
    int64_t created = 0, modified = 0;
};

struct UserEntry {
    int64_t id = 0;
    std::string username, role;
    int64_t created = 0, lastLogin = 0;
};

struct TransferEntry {
    int64_t id = 0, userId = 0;
    std::string username, direction, path;
    uint64_t size = 0;
    std::string sha256, status, detail, clientAddr;
    int64_t started = 0, finished = 0;
};

struct AuditEntry {
    int64_t id = 0, ts = 0, userId = 0;
    std::string username, action, target, result, clientAddr, detail;
};

using KeyValues = std::vector<std::pair<std::string, std::string>>;

void write(Writer& w, const FileEntry& e);
void write(Writer& w, const UserEntry& e);
void write(Writer& w, const TransferEntry& e);
void write(Writer& w, const AuditEntry& e);
FileEntry readFileEntry(Reader& r);
UserEntry readUserEntry(Reader& r);
TransferEntry readTransferEntry(Reader& r);
AuditEntry readAuditEntry(Reader& r);

template <typename T>
void writeList(Writer& w, const std::vector<T>& v) {
    w.u32(uint32_t(v.size()));
    for (const auto& e : v) write(w, e);
}
void writeKeyValues(Writer& w, const KeyValues& kv);
KeyValues readKeyValues(Reader& r);

std::string formatTime(int64_t unixSeconds);  // local "YYYY-MM-DD HH:MM:SS"
std::string humanSize(uint64_t bytes);

}  // namespace linsft
