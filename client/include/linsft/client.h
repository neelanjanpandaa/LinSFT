// Client library shared by the CLI, the Qt GUI and the test-suite.
#pragma once
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "linsft/models.h"
#include "linsft/permissions.h"
#include "linsft/protocol.h"

namespace linsft {

struct Result {
    bool ok = false;
    Status status = Status::NETWORK;
    std::string message;
    explicit operator bool() const { return ok; }
};

class Client {
public:
    // Return false to cancel the transfer.
    using Progress = std::function<bool(uint64_t done, uint64_t total)>;

    Client() = default;
    ~Client() { disconnect(); }
    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;

    Result connectTo(const std::string& host, uint16_t port, int timeoutSeconds = 30);
    void disconnect();
    bool connected() const { return fd_ >= 0; }
    int socketFd() const { return fd_; }  // exposed for protocol-level tests

    Result ping();
    Result registerUser(const std::string& user, const std::string& pass);
    Result login(const std::string& user, const std::string& pass);
    Result logout();
    bool loggedIn() const { return !token_.empty(); }
    const std::string& username() const { return username_; }
    Role role() const { return role_; }
    int64_t userId() const { return userId_; }
    const std::string& token() const { return token_; }
    void setToken(const std::string& t) { token_ = t; }  // for tests (forged/expired tokens)

    Result list(const std::string& path, std::vector<FileEntry>& out);
    Result search(const std::string& query, std::vector<FileEntry>& out);
    Result info(const std::string& path, FileEntry& out);
    Result rename(const std::string& path, const std::string& newName, std::string* newPath = nullptr);
    Result removeFile(const std::string& path);
    Result makeDir(const std::string& path);
    Result removeDir(const std::string& path);
    Result setShared(const std::string& path, bool shared);

    Result upload(const std::string& localPath, const std::string& remoteDir, const std::string& remoteName,
                  bool shared = false, bool overwrite = false, Progress progress = nullptr);
    Result download(const std::string& remotePath, const std::string& localPath, bool overwriteLocal = false,
                    Progress progress = nullptr, std::string* sha256Out = nullptr);

    Result history(uint32_t limit, std::vector<TransferEntry>& out);
    Result listUsers(std::vector<UserEntry>& out);
    Result setUserRole(const std::string& user, const std::string& role);
    Result deleteUser(const std::string& user);
    Result audit(uint32_t limit, std::vector<AuditEntry>& out);
    Result sysinfo(KeyValues& out);

    // Low level: send an arbitrary request (token is NOT added automatically) and return the reply.
    Result rawCall(MsgType type, const Writer& body, std::vector<uint8_t>& replyPayload, size_t& bodyOffset);

private:
    Result callSimple(MsgType type, Writer& body);
    Writer authed() const;

    int fd_ = -1;
    uint32_t nextId_ = 1;
    std::string token_, username_;
    Role role_ = Role::STUDENT;
    int64_t userId_ = 0;
};

}  // namespace linsft
