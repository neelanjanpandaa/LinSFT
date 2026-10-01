#include "linsft/protocol.h"

#include <sys/socket.h>
#include <sys/types.h>

#include <cerrno>
#include <cstring>

namespace linsft {

const char* statusName(Status s) {
    switch (s) {
        case Status::OK: return "OK";
        case Status::BAD_REQUEST: return "BAD_REQUEST";
        case Status::AUTH_REQUIRED: return "AUTH_REQUIRED";
        case Status::AUTH_FAILED: return "AUTH_FAILED";
        case Status::FORBIDDEN: return "FORBIDDEN";
        case Status::NOT_FOUND: return "NOT_FOUND";
        case Status::EXISTS: return "EXISTS";
        case Status::INVALID_PATH: return "INVALID_PATH";
        case Status::CHECKSUM_MISMATCH: return "CHECKSUM_MISMATCH";
        case Status::TOO_LARGE: return "TOO_LARGE";
        case Status::NOT_EMPTY: return "NOT_EMPTY";
        case Status::BUSY: return "BUSY";
        case Status::LOCKED_OUT: return "LOCKED_OUT";
        case Status::INTERNAL: return "INTERNAL";
        case Status::IO_ERROR: return "IO_ERROR";
        case Status::NETWORK: return "NETWORK";
    }
    return "UNKNOWN";
}

bool isKnownMsgType(uint16_t t) {
    switch (MsgType(t)) {
        case MsgType::PING: case MsgType::REGISTER: case MsgType::LOGIN: case MsgType::LOGOUT:
        case MsgType::LIST: case MsgType::SEARCH: case MsgType::INFO: case MsgType::RENAME:
        case MsgType::DELETE_FILE: case MsgType::MKDIR: case MsgType::RMDIR: case MsgType::SHARE:
        case MsgType::UPLOAD_BEGIN: case MsgType::UPLOAD_CHUNK: case MsgType::UPLOAD_END:
        case MsgType::UPLOAD_ABORT: case MsgType::DOWNLOAD_BEGIN: case MsgType::DOWNLOAD_CHUNK:
        case MsgType::DOWNLOAD_END: case MsgType::HISTORY: case MsgType::USERS_LIST:
        case MsgType::USER_SET_ROLE: case MsgType::USER_DELETE: case MsgType::AUDIT:
        case MsgType::SYSINFO:
            return true;
    }
    return false;
}

const char* msgTypeName(uint16_t type) {
    switch (MsgType(type & ~RESPONSE_FLAG)) {
        case MsgType::PING: return "PING";
        case MsgType::REGISTER: return "REGISTER";
        case MsgType::LOGIN: return "LOGIN";
        case MsgType::LOGOUT: return "LOGOUT";
        case MsgType::LIST: return "LIST";
        case MsgType::SEARCH: return "SEARCH";
        case MsgType::INFO: return "INFO";
        case MsgType::RENAME: return "RENAME";
        case MsgType::DELETE_FILE: return "DELETE";
        case MsgType::MKDIR: return "MKDIR";
        case MsgType::RMDIR: return "RMDIR";
        case MsgType::SHARE: return "SHARE";
        case MsgType::UPLOAD_BEGIN: return "UPLOAD_BEGIN";
        case MsgType::UPLOAD_CHUNK: return "UPLOAD_CHUNK";
        case MsgType::UPLOAD_END: return "UPLOAD_END";
        case MsgType::UPLOAD_ABORT: return "UPLOAD_ABORT";
        case MsgType::DOWNLOAD_BEGIN: return "DOWNLOAD_BEGIN";
        case MsgType::DOWNLOAD_CHUNK: return "DOWNLOAD_CHUNK";
        case MsgType::DOWNLOAD_END: return "DOWNLOAD_END";
        case MsgType::HISTORY: return "HISTORY";
        case MsgType::USERS_LIST: return "USERS_LIST";
        case MsgType::USER_SET_ROLE: return "USER_SET_ROLE";
        case MsgType::USER_DELETE: return "USER_DELETE";
        case MsgType::AUDIT: return "AUDIT";
        case MsgType::SYSINFO: return "SYSINFO";
    }
    return "UNKNOWN";
}

// ---- Writer -------------------------------------------------------------
Writer& Writer::u8(uint8_t v) { buf_.push_back(v); return *this; }
Writer& Writer::u16(uint16_t v) {
    buf_.push_back(uint8_t(v >> 8)); buf_.push_back(uint8_t(v)); return *this;
}
Writer& Writer::u32(uint32_t v) {
    for (int s = 24; s >= 0; s -= 8) buf_.push_back(uint8_t(v >> s));
    return *this;
}
Writer& Writer::u64(uint64_t v) {
    for (int s = 56; s >= 0; s -= 8) buf_.push_back(uint8_t(v >> s));
    return *this;
}
Writer& Writer::str(const std::string& s) { return bytes(s.data(), s.size()); }
Writer& Writer::bytes(const void* data, size_t len) {
    u32(uint32_t(len));
    const uint8_t* p = static_cast<const uint8_t*>(data);
    buf_.insert(buf_.end(), p, p + len);
    return *this;
}

// ---- Reader -------------------------------------------------------------
void Reader::need(size_t n) const {
    if (n_ - pos_ < n) throw ProtocolError("truncated message");
}
uint8_t Reader::u8() { need(1); return p_[pos_++]; }
uint16_t Reader::u16() { need(2); uint16_t v = uint16_t(p_[pos_] << 8 | p_[pos_ + 1]); pos_ += 2; return v; }
uint32_t Reader::u32() {
    need(4);
    uint32_t v = 0;
    for (int i = 0; i < 4; ++i) v = (v << 8) | p_[pos_ + i];
    pos_ += 4;
    return v;
}
uint64_t Reader::u64() {
    need(8);
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | p_[pos_ + i];
    pos_ += 8;
    return v;
}
std::string Reader::str(size_t maxLen) {
    uint32_t len = u32();
    if (len > maxLen) throw ProtocolError("string field too long");
    need(len);
    std::string s(reinterpret_cast<const char*>(p_ + pos_), len);
    pos_ += len;
    return s;
}
std::vector<uint8_t> Reader::bytes(size_t maxLen) {
    uint32_t len = u32();
    if (len > maxLen) throw ProtocolError("byte field too long");
    need(len);
    std::vector<uint8_t> v(p_ + pos_, p_ + pos_ + len);
    pos_ += len;
    return v;
}
void Reader::expectEnd() const {
    if (pos_ != n_) throw ProtocolError("unexpected trailing bytes");
}

// ---- Framing ------------------------------------------------------------
void encodeHeader(const Header& h, uint8_t out[HEADER_SIZE]) {
    out[0] = uint8_t(h.magic >> 24); out[1] = uint8_t(h.magic >> 16);
    out[2] = uint8_t(h.magic >> 8);  out[3] = uint8_t(h.magic);
    out[4] = h.version; out[5] = h.flags;
    out[6] = uint8_t(h.type >> 8); out[7] = uint8_t(h.type);
    for (int i = 0; i < 4; ++i) out[8 + i] = uint8_t(h.requestId >> (24 - 8 * i));
    for (int i = 0; i < 4; ++i) out[12 + i] = uint8_t(h.payloadLen >> (24 - 8 * i));
}

bool decodeHeader(const uint8_t in[HEADER_SIZE], Header& h, std::string& err) {
    h.magic = (uint32_t(in[0]) << 24) | (uint32_t(in[1]) << 16) | (uint32_t(in[2]) << 8) | in[3];
    h.version = in[4];
    h.flags = in[5];
    h.type = uint16_t(in[6] << 8 | in[7]);
    h.requestId = 0;
    for (int i = 0; i < 4; ++i) h.requestId = (h.requestId << 8) | in[8 + i];
    h.payloadLen = 0;
    for (int i = 0; i < 4; ++i) h.payloadLen = (h.payloadLen << 8) | in[12 + i];
    if (h.magic != PROTO_MAGIC) { err = "bad magic"; return false; }
    if (h.version != PROTO_VERSION) { err = "unsupported protocol version"; return false; }
    if (h.payloadLen > MAX_PAYLOAD) { err = "payload exceeds maximum size"; return false; }
    return true;
}

std::vector<uint8_t> encodeMessage(const Message& m) {
    std::vector<uint8_t> out(HEADER_SIZE + m.payload.size());
    Header h;
    h.type = m.type;
    h.requestId = m.requestId;
    h.payloadLen = uint32_t(m.payload.size());
    encodeHeader(h, out.data());
    if (!m.payload.empty()) std::memcpy(out.data() + HEADER_SIZE, m.payload.data(), m.payload.size());
    return out;
}

Message makeRequest(MsgType type, uint32_t id, const Writer& body) {
    Message m;
    m.type = uint16_t(type);
    m.requestId = id;
    m.payload = body.data();
    return m;
}

Message makeResponse(uint16_t reqType, uint32_t reqId, Status st, const std::string& msg,
                     const Writer* body) {
    Writer w;
    w.u16(uint16_t(st)).str(msg);
    Message m;
    m.type = uint16_t(reqType | RESPONSE_FLAG);
    m.requestId = reqId;
    m.payload = w.release();
    if (body) m.payload.insert(m.payload.end(), body->data().begin(), body->data().end());
    return m;
}

// ---- Socket I/O ---------------------------------------------------------
bool sendAll(int fd, const void* data, size_t len, std::string& err) {
    const uint8_t* p = static_cast<const uint8_t*>(data);
    size_t sent = 0;
    while (sent < len) {
        ssize_t r = ::send(fd, p + sent, len - sent, MSG_NOSIGNAL);
        if (r < 0) {
            if (errno == EINTR) continue;
            err = std::string("send: ") + std::strerror(errno);
            return false;
        }
        sent += size_t(r);
    }
    return true;
}

IoResult recvAll(int fd, void* data, size_t len, std::string& err, bool atBoundary) {
    uint8_t* p = static_cast<uint8_t*>(data);
    size_t got = 0;
    while (got < len) {
        ssize_t r = ::recv(fd, p + got, len - got, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) { err = "receive timed out"; return IoResult::TIMEOUT; }
            err = std::string("recv: ") + std::strerror(errno);
            return IoResult::ERROR;
        }
        if (r == 0) {
            if (got == 0 && atBoundary) return IoResult::CLOSED;
            err = "connection closed mid-message";
            return IoResult::ERROR;
        }
        got += size_t(r);
    }
    return IoResult::OK;
}

bool sendMessage(int fd, const Message& m, std::string& err) {
    std::vector<uint8_t> frame = encodeMessage(m);  // single send keeps header+payload together
    return sendAll(fd, frame.data(), frame.size(), err);
}

IoResult recvMessage(int fd, Message& m, std::string& err) {
    uint8_t hdr[HEADER_SIZE];
    IoResult r = recvAll(fd, hdr, HEADER_SIZE, err, true);
    if (r != IoResult::OK) return r;
    Header h;
    if (!decodeHeader(hdr, h, err)) return IoResult::PROTOCOL;
    m.type = h.type;
    m.requestId = h.requestId;
    m.payload.assign(h.payloadLen, 0);
    if (h.payloadLen > 0) {
        r = recvAll(fd, m.payload.data(), h.payloadLen, err, false);
        if (r != IoResult::OK) return r;
    }
    return IoResult::OK;
}

}  // namespace linsft
