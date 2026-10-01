// SHA-256, HMAC-SHA256, PBKDF2-HMAC-SHA256 and secure randomness (/dev/urandom).
#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace linsft {

class Sha256 {
public:
    static constexpr size_t DIGEST_SIZE = 32;
    using Digest = std::array<uint8_t, DIGEST_SIZE>;

    Sha256() { reset(); }
    void reset();
    void update(const void* data, size_t len);
    Digest finish();  // finalises; call reset() before reuse

    static Digest hash(const void* data, size_t len);
    static std::string hashHex(const std::string& s);

private:
    void transform(const uint8_t block[64]);
    uint32_t state_[8];
    uint64_t totalLen_;
    uint8_t buf_[64];
    size_t bufLen_;
};

class HmacSha256 {
public:
    HmacSha256(const uint8_t* key, size_t keyLen);
    Sha256::Digest compute(const uint8_t* msg, size_t len) const;
private:
    Sha256 inner_, outer_;
};

std::string toHex(const uint8_t* data, size_t len);
std::string toHex(const Sha256::Digest& d);
bool fromHex(const std::string& hex, std::vector<uint8_t>& out);

std::vector<uint8_t> pbkdf2HmacSha256(const std::string& password, const uint8_t* salt,
                                      size_t saltLen, uint32_t iterations, size_t dkLen);

// Reads from the kernel's /dev/urandom character device using open()/read().
bool randomBytes(uint8_t* out, size_t n);
std::string randomHex(size_t nBytes);

bool constantTimeEquals(const std::string& a, const std::string& b);

// Streams a file with POSIX open()/read() and returns its SHA-256 (hex).
bool sha256File(const std::string& path, std::string& hexOut, std::string& err);

}  // namespace linsft
