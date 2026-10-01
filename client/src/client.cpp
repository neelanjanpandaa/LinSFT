#include "linsft/client.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

#include "linsft/crypto.h"

namespace linsft {

static Result fail(Status st, const std::string& m) { Result r; r.ok = false; r.status = st; r.message = m; return r; }

Result Client::connectTo(const std::string& host, uint16_t port, int timeoutSeconds) {
    disconnect();
    addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    int gai = getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res);
    if (gai != 0) return fail(Status::NETWORK, std::string("cannot resolve host: ") + gai_strerror(gai));
    std::string lastErr = "no addresses";
    for (addrinfo* p = res; p; p = p->ai_next) {
        int fd = ::socket(p->ai_family, p->ai_socktype | SOCK_CLOEXEC, p->ai_protocol);
        if (fd < 0) { lastErr = std::strerror(errno); continue; }
        if (::connect(fd, p->ai_addr, p->ai_addrlen) == 0) {
            int one = 1;
            ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
            timeval tv{timeoutSeconds, 0};
            ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
            fd_ = fd;
            freeaddrinfo(res);
            Result r; r.ok = true; r.status = Status::OK; r.message = "connected";
            return r;
        }
        lastErr = std::strerror(errno);
        ::close(fd);
    }
    freeaddrinfo(res);
    return fail(Status::NETWORK, "connect to " + host + ":" + std::to_string(port) + " failed: " + lastErr);
}

void Client::disconnect() {
    if (fd_ >= 0) { ::close(fd_); fd_ = -1; }
    token_.clear();
    username_.clear();
}

Writer Client::authed() const { Writer w; w.str(token_); return w; }

Result Client::rawCall(MsgType type, const Writer& body, std::vector<uint8_t>& payload, size_t& off) {
    if (fd_ < 0) return fail(Status::NETWORK, "not connected");
    uint32_t id = nextId_++;
    std::string err;
    if (!sendMessage(fd_, makeRequest(type, id, body), err)) { disconnect(); return fail(Status::NETWORK, err); }
    Message resp;
    IoResult r = recvMessage(fd_, resp, err);
    if (r == IoResult::CLOSED) { disconnect(); return fail(Status::NETWORK, "server closed the connection"); }
    if (r != IoResult::OK) { disconnect(); return fail(Status::NETWORK, err); }
    if (resp.type != (uint16_t(type) | RESPONSE_FLAG) && resp.type != RESPONSE_FLAG) {
        disconnect();
        return fail(Status::NETWORK, "unexpected response type");
    }
    try {
        Reader rd(resp.payload);
        uint16_t st = rd.u16();
        std::string msg = rd.str(65536);
        off = resp.payload.size() - rd.remaining();
        payload = std::move(resp.payload);
        Result res;
        res.status = Status(st);
        res.message = msg;
        res.ok = (res.status == Status::OK);
        return res;
    } catch (const ProtocolError& e) {
        disconnect();
        return fail(Status::NETWORK, std::string("bad response: ") + e.what());
    }
}

Result Client::callSimple(MsgType type, Writer& body) {
    std::vector<uint8_t> p;
    size_t off = 0;
    return rawCall(type, body, p, off);
}

#define NEED_LOGIN() if (token_.empty()) return fail(Status::AUTH_REQUIRED, "not logged in")

Result Client::ping() { Writer w; return callSimple(MsgType::PING, w); }

Result Client::registerUser(const std::string& u, const std::string& p) {
    Writer w; w.str(u).str(p);
    return callSimple(MsgType::REGISTER, w);
}

Result Client::login(const std::string& u, const std::string& p) {
    Writer w; w.str(u).str(p);
    std::vector<uint8_t> payload; size_t off = 0;
    Result r = rawCall(MsgType::LOGIN, w, payload, off);
    if (!r.ok) return r;
    try {
        Reader rd(payload.data() + off, payload.size() - off);
        token_ = rd.str(128);
        userId_ = rd.i64();
        username_ = rd.str(128);
        std::string role = rd.str(32);
        if (!parseRole(role, role_)) throw ProtocolError("bad role");
    } catch (const ProtocolError& e) {
        token_.clear();
        return fail(Status::NETWORK, std::string("bad login response: ") + e.what());
    }
    return r;
}

Result Client::logout() {
    NEED_LOGIN();
    Writer w = authed();
    Result r = callSimple(MsgType::LOGOUT, w);
    token_.clear();
    username_.clear();
    return r;
}

#define PARSE_LIST(T, reader)                                                          \
    if (!r.ok) return r;                                                               \
    try {                                                                              \
        Reader rd(payload.data() + off, payload.size() - off);                         \
        uint32_t n = rd.u32();                                                         \
        if (n > 100000) throw ProtocolError("too many entries");                       \
        out.clear();                                                                   \
        for (uint32_t i = 0; i < n; ++i) out.push_back(reader(rd));                    \
    } catch (const ProtocolError& e) { return fail(Status::NETWORK, std::string("bad response: ") + e.what()); } \
    return r;

Result Client::list(const std::string& path, std::vector<FileEntry>& out) {
    NEED_LOGIN();
    Writer w = authed(); w.str(path);
    std::vector<uint8_t> payload; size_t off = 0;
    Result r = rawCall(MsgType::LIST, w, payload, off);
    PARSE_LIST(FileEntry, readFileEntry)
}

Result Client::search(const std::string& q, std::vector<FileEntry>& out) {
    NEED_LOGIN();
    Writer w = authed(); w.str(q);
    std::vector<uint8_t> payload; size_t off = 0;
    Result r = rawCall(MsgType::SEARCH, w, payload, off);
    PARSE_LIST(FileEntry, readFileEntry)
}

Result Client::info(const std::string& path, FileEntry& out) {
    NEED_LOGIN();
    Writer w = authed(); w.str(path);
    std::vector<uint8_t> payload; size_t off = 0;
    Result r = rawCall(MsgType::INFO, w, payload, off);
    if (!r.ok) return r;
    try { Reader rd(payload.data() + off, payload.size() - off); out = readFileEntry(rd); }
    catch (const ProtocolError& e) { return fail(Status::NETWORK, std::string("bad response: ") + e.what()); }
    return r;
}

Result Client::rename(const std::string& path, const std::string& newName, std::string* newPath) {
    NEED_LOGIN();
    Writer w = authed(); w.str(path).str(newName);
    std::vector<uint8_t> payload; size_t off = 0;
    Result r = rawCall(MsgType::RENAME, w, payload, off);
    if (r.ok && newPath) {
        try { Reader rd(payload.data() + off, payload.size() - off); *newPath = rd.str(); } catch (const ProtocolError&) {}
    }
    return r;
}

Result Client::removeFile(const std::string& path) { NEED_LOGIN(); Writer w = authed(); w.str(path); return callSimple(MsgType::DELETE_FILE, w); }
Result Client::makeDir(const std::string& path) { NEED_LOGIN(); Writer w = authed(); w.str(path); return callSimple(MsgType::MKDIR, w); }
Result Client::removeDir(const std::string& path) { NEED_LOGIN(); Writer w = authed(); w.str(path); return callSimple(MsgType::RMDIR, w); }
Result Client::setShared(const std::string& path, bool s) { NEED_LOGIN(); Writer w = authed(); w.str(path).boolean(s); return callSimple(MsgType::SHARE, w); }

Result Client::history(uint32_t limit, std::vector<TransferEntry>& out) {
    NEED_LOGIN();
    Writer w = authed(); w.u32(limit);
    std::vector<uint8_t> payload; size_t off = 0;
    Result r = rawCall(MsgType::HISTORY, w, payload, off);
    PARSE_LIST(TransferEntry, readTransferEntry)
}
Result Client::listUsers(std::vector<UserEntry>& out) {
    NEED_LOGIN();
    Writer w = authed();
    std::vector<uint8_t> payload; size_t off = 0;
    Result r = rawCall(MsgType::USERS_LIST, w, payload, off);
    PARSE_LIST(UserEntry, readUserEntry)
}
Result Client::audit(uint32_t limit, std::vector<AuditEntry>& out) {
    NEED_LOGIN();
    Writer w = authed(); w.u32(limit);
    std::vector<uint8_t> payload; size_t off = 0;
    Result r = rawCall(MsgType::AUDIT, w, payload, off);
    PARSE_LIST(AuditEntry, readAuditEntry)
}
Result Client::setUserRole(const std::string& u, const std::string& role) {
    NEED_LOGIN(); Writer w = authed(); w.str(u).str(role); return callSimple(MsgType::USER_SET_ROLE, w);
}
Result Client::deleteUser(const std::string& u) { NEED_LOGIN(); Writer w = authed(); w.str(u); return callSimple(MsgType::USER_DELETE, w); }
Result Client::sysinfo(KeyValues& out) {
    NEED_LOGIN();
    Writer w = authed();
    std::vector<uint8_t> payload; size_t off = 0;
    Result r = rawCall(MsgType::SYSINFO, w, payload, off);
    if (!r.ok) return r;
    try { Reader rd(payload.data() + off, payload.size() - off); out = readKeyValues(rd); }
    catch (const ProtocolError& e) { return fail(Status::NETWORK, std::string("bad response: ") + e.what()); }
    return r;
}

// ---- file transfer ------------------------------------------------------
Result Client::upload(const std::string& localPath, const std::string& remoteDir, const std::string& remoteName,
                      bool shared, bool overwrite, Progress progress) {
    NEED_LOGIN();
    int fd = ::open(localPath.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return fail(Status::IO_ERROR, "cannot open '" + localPath + "': " + std::strerror(errno));
    struct FdGuard { int fd; ~FdGuard() { if (fd >= 0) ::close(fd); } } guard{fd};
    struct stat st;
    if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) return fail(Status::IO_ERROR, "'" + localPath + "' is not a regular file");
    uint64_t size = uint64_t(st.st_size);

    // pass 1: SHA-256 (streamed, constant memory)
    Sha256 h;
    std::vector<uint8_t> buf(CHUNK_SIZE);
    for (;;) {
        ssize_t n = ::read(fd, buf.data(), buf.size());
        if (n < 0) { if (errno == EINTR) continue; return fail(Status::IO_ERROR, std::string("read: ") + std::strerror(errno)); }
        if (n == 0) break;
        h.update(buf.data(), size_t(n));
    }
    std::string sha = toHex(h.finish());
    if (::lseek(fd, 0, SEEK_SET) < 0) return fail(Status::IO_ERROR, "lseek failed");

    Writer w = authed();
    w.str(remoteDir).str(remoteName).u64(size).str(sha).boolean(shared).boolean(overwrite);
    std::vector<uint8_t> payload; size_t off = 0;
    Result r = rawCall(MsgType::UPLOAD_BEGIN, w, payload, off);
    if (!r.ok) return r;
    uint32_t tid = 0;
    try { Reader rd(payload.data() + off, payload.size() - off); tid = rd.u32(); rd.u32(); }
    catch (const ProtocolError& e) { return fail(Status::NETWORK, std::string("bad response: ") + e.what()); }

    auto abort = [&]() {
        Writer a = authed(); a.u32(tid);
        if (connected()) callSimple(MsgType::UPLOAD_ABORT, a);
    };
    uint64_t sent = 0;
    if (progress && !progress(0, size)) { abort(); return fail(Status::IO_ERROR, "cancelled"); }
    while (sent < size) {
        size_t want = size_t(std::min<uint64_t>(CHUNK_SIZE, size - sent));
        size_t got = 0;
        while (got < want) {
            ssize_t n = ::read(fd, buf.data() + got, want - got);
            if (n < 0) { if (errno == EINTR) continue; abort(); return fail(Status::IO_ERROR, std::string("read: ") + std::strerror(errno)); }
            if (n == 0) { abort(); return fail(Status::IO_ERROR, "file shrank while uploading"); }
            got += size_t(n);
        }
        Writer c = authed(); c.u32(tid).bytes(buf.data(), got);
        r = callSimple(MsgType::UPLOAD_CHUNK, c);
        if (!r.ok) return r;
        sent += got;
        if (progress && !progress(sent, size)) { abort(); return fail(Status::IO_ERROR, "cancelled"); }
    }
    Writer e = authed(); e.u32(tid);
    return callSimple(MsgType::UPLOAD_END, e);
}

Result Client::download(const std::string& remotePath, const std::string& localPath, bool overwriteLocal,
                        Progress progress, std::string* shaOut) {
    NEED_LOGIN();
    struct stat lst;
    if (!overwriteLocal && ::lstat(localPath.c_str(), &lst) == 0)
        return fail(Status::EXISTS, "local file '" + localPath + "' already exists");
    Writer w = authed(); w.str(remotePath);
    std::vector<uint8_t> payload; size_t off = 0;
    Result r = rawCall(MsgType::DOWNLOAD_BEGIN, w, payload, off);
    if (!r.ok) return r;
    uint32_t tid = 0; uint64_t size = 0; std::string expected;
    try {
        Reader rd(payload.data() + off, payload.size() - off);
        tid = rd.u32(); size = rd.u64(); expected = rd.str(128); rd.str(512);
    } catch (const ProtocolError& e) { return fail(Status::NETWORK, std::string("bad response: ") + e.what()); }

    std::string part = localPath + ".part";
    int fd = ::open(part.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0644);
    auto endRemote = [&](bool ok) { Writer e = authed(); e.u32(tid).boolean(ok); if (connected()) callSimple(MsgType::DOWNLOAD_END, e); };
    if (fd < 0) { endRemote(false); return fail(Status::IO_ERROR, "cannot create '" + part + "': " + std::strerror(errno)); }
    auto cleanup = [&](bool ok) { if (fd >= 0) { ::close(fd); fd = -1; } ::unlink(part.c_str()); endRemote(ok); };

    Sha256 h;
    uint64_t got = 0;
    if (progress && !progress(0, size)) { cleanup(false); return fail(Status::IO_ERROR, "cancelled"); }
    for (bool eof = false; !eof;) {
        Writer c = authed(); c.u32(tid);
        r = rawCall(MsgType::DOWNLOAD_CHUNK, c, payload, off);
        if (!r.ok) { if (fd >= 0) { ::close(fd); ::unlink(part.c_str()); } return r; }
        std::vector<uint8_t> data;
        try {
            Reader rd(payload.data() + off, payload.size() - off);
            data = rd.bytes(CHUNK_SIZE * 2);
            eof = rd.boolean();
        } catch (const ProtocolError& e) { cleanup(false); return fail(Status::NETWORK, std::string("bad response: ") + e.what()); }
        size_t o = 0;
        while (o < data.size()) {
            ssize_t n = ::write(fd, data.data() + o, data.size() - o);
            if (n < 0) { if (errno == EINTR) continue; std::string why = std::strerror(errno); cleanup(false); return fail(Status::IO_ERROR, "write: " + why); }
            o += size_t(n);
        }
        h.update(data.data(), data.size());
        got += data.size();
        if (got > size) { cleanup(false); return fail(Status::BAD_REQUEST, "server sent more data than announced"); }
        if (progress && !progress(got, size)) { cleanup(false); return fail(Status::IO_ERROR, "cancelled"); }
    }
    std::string actual = toHex(h.finish());
    if (shaOut) *shaOut = actual;
    bool good = (got == size) && constantTimeEquals(actual, expected);
    if (!good) {
        cleanup(false);
        return fail(Status::CHECKSUM_MISMATCH, "SHA-256 mismatch: downloaded data does not match the server's checksum");
    }
    if (::fsync(fd) != 0) { std::string why = std::strerror(errno); cleanup(false); return fail(Status::IO_ERROR, "fsync: " + why); }
    ::close(fd); fd = -1;
    if (::rename(part.c_str(), localPath.c_str()) != 0) {
        std::string why = std::strerror(errno);
        ::unlink(part.c_str());
        endRemote(false);
        return fail(Status::IO_ERROR, "cannot move into place: " + why);
    }
    endRemote(true);
    Result ok; ok.ok = true; ok.status = Status::OK; ok.message = "downloaded " + humanSize(got) + ", SHA-256 verified";
    return ok;
}

}  // namespace linsft
