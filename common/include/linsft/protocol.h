// LinSFT custom binary protocol: framing, (de)serialisation and robust socket I/O.
//
// Frame layout (all integers big-endian / network byte order):
//   offset 0  u32  magic      0x4C534654 ("LSFT")
//   offset 4  u8   version    1
//   offset 5  u8   flags      reserved (0)
//   offset 6  u16  type       MsgType (responses set bit 0x8000)
//   offset 8  u32  requestId  echoed in the response
//   offset 12 u32  length     payload size in bytes (<= MAX_PAYLOAD)
//   offset 16 ...  payload
// Response payload: u16 status, str message, then command specific fields.
#pragma once
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace linsft {

constexpr uint32_t PROTO_MAGIC = 0x4C534654;
constexpr uint8_t PROTO_VERSION = 1;
constexpr size_t HEADER_SIZE = 16;
constexpr uint32_t MAX_PAYLOAD = 1024 * 1024;   // hard cap on any frame payload
constexpr size_t CHUNK_SIZE = 64 * 1024;        // file transfer chunk
constexpr uint16_t RESPONSE_FLAG = 0x8000;

enum class MsgType : uint16_t {
    PING = 1,
    REGISTER = 2,
    LOGIN = 3,
    LOGOUT = 4,
    LIST = 10,
    SEARCH = 11,
    INFO = 12,
    RENAME = 13,
    DELETE_FILE = 14,
    MKDIR = 15,
    RMDIR = 16,
    SHARE = 17,
    UPLOAD_BEGIN = 20,
    UPLOAD_CHUNK = 21,
    UPLOAD_END = 22,
    UPLOAD_ABORT = 23,
    DOWNLOAD_BEGIN = 30,
    DOWNLOAD_CHUNK = 31,
    DOWNLOAD_END = 32,
    HISTORY = 40,
    USERS_LIST = 50,
    USER_SET_ROLE = 51,
    USER_DELETE = 52,
    AUDIT = 53,
    SYSINFO = 60,
};

enum class Status : uint16_t {
    OK = 0,
    BAD_REQUEST = 1,
    AUTH_REQUIRED = 2,
    AUTH_FAILED = 3,
    FORBIDDEN = 4,
    NOT_FOUND = 5,
    EXISTS = 6,
    INVALID_PATH = 7,
    CHECKSUM_MISMATCH = 8,
    TOO_LARGE = 9,
    NOT_EMPTY = 10,
    BUSY = 11,
    LOCKED_OUT = 12,
    INTERNAL = 13,
    IO_ERROR = 14,
    NETWORK = 15,  // client side only: transport failure
};

const char* statusName(Status s);
const char* msgTypeName(uint16_t type);
bool isKnownMsgType(uint16_t type);

class ProtocolError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

struct Header {
    uint32_t magic = PROTO_MAGIC;
    uint8_t version = PROTO_VERSION;
    uint8_t flags = 0;
    uint16_t type = 0;
    uint32_t requestId = 0;
    uint32_t payloadLen = 0;
};

struct Message {
    uint16_t type = 0;
    uint32_t requestId = 0;
    std::vector<uint8_t> payload;
};

// Appends big-endian fields to a buffer.
class Writer {
public:
    Writer& u8(uint8_t v);
    Writer& u16(uint16_t v);
    Writer& u32(uint32_t v);
    Writer& u64(uint64_t v);
    Writer& i64(int64_t v) { return u64(uint64_t(v)); }
    Writer& boolean(bool v) { return u8(v ? 1 : 0); }
    Writer& str(const std::string& s);
    Writer& bytes(const void* data, size_t len);  // u32 length + data
    const std::vector<uint8_t>& data() const { return buf_; }
    std::vector<uint8_t> release() { return std::move(buf_); }
    size_t size() const { return buf_.size(); }
private:
    std::vector<uint8_t> buf_;
};

// Bounds-checked reader; throws ProtocolError on truncated/oversized fields.
class Reader {
public:
    Reader(const uint8_t* p, size_t n) : p_(p), n_(n) {}
    explicit Reader(const std::vector<uint8_t>& v) : p_(v.data()), n_(v.size()) {}
    uint8_t u8();
    uint16_t u16();
    uint32_t u32();
    uint64_t u64();
    int64_t i64() { return int64_t(u64()); }
    bool boolean() { return u8() != 0; }
    std::string str(size_t maxLen = 4096);
    std::vector<uint8_t> bytes(size_t maxLen = MAX_PAYLOAD);
    size_t remaining() const { return n_ - pos_; }
    void expectEnd() const;
private:
    void need(size_t n) const;
    const uint8_t* p_;
    size_t n_;
    size_t pos_ = 0;
};

// Header helpers
void encodeHeader(const Header& h, uint8_t out[HEADER_SIZE]);
bool decodeHeader(const uint8_t in[HEADER_SIZE], Header& h, std::string& err);  // validates
std::vector<uint8_t> encodeMessage(const Message& m);

// Response helpers
Message makeRequest(MsgType type, uint32_t id, const Writer& body);
Message makeResponse(uint16_t reqType, uint32_t reqId, Status st, const std::string& msg,
                     const Writer* body = nullptr);

// Robust socket I/O (handles EINTR, partial reads/writes, SIGPIPE via MSG_NOSIGNAL)
enum class IoResult { OK, CLOSED, TIMEOUT, ERROR, PROTOCOL };
bool sendAll(int fd, const void* data, size_t len, std::string& err);
IoResult recvAll(int fd, void* data, size_t len, std::string& err, bool atBoundary);
bool sendMessage(int fd, const Message& m, std::string& err);
IoResult recvMessage(int fd, Message& m, std::string& err);

}  // namespace linsft
