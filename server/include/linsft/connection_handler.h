// Per-connection request loop: decodes frames, authenticates, authorises via PermissionService,
// delegates to the managers and writes the response.
#pragma once
#include <string>

#include "linsft/protocol.h"
#include "linsft/server.h"

namespace linsft {

class ConnectionHandler {
public:
    ConnectionHandler(Services& svc, int fd, std::string addr);
    void run();

private:
    bool dispatch(const Message& m);
    void reply(const Message& req, Status st, const std::string& msg, const Writer* body = nullptr);
    bool authenticate(Reader& r, Session& s);
    bool readPath(const Message& m, Reader& r, const Session* s, const char* action, std::string& out);
    void deny(const Message& m, const Session& s, const char* action, const std::string& target);
    void audit(const Session& s, const char* action, const std::string& target, const char* result,
               const std::string& detail = "", bool echo = true);
    void ensureHome(const std::string& username, int64_t userId);

    void hRegister(const Message&, Reader&);
    void hLogin(const Message&, Reader&);
    void hLogout(const Message&, Reader&);
    void hList(const Message&, Reader&);
    void hSearch(const Message&, Reader&);
    void hInfo(const Message&, Reader&);
    void hRename(const Message&, Reader&);
    void hDelete(const Message&, Reader&);
    void hMkdir(const Message&, Reader&);
    void hRmdir(const Message&, Reader&);
    void hShare(const Message&, Reader&);
    void hUploadBegin(const Message&, Reader&);
    void hUploadChunk(const Message&, Reader&);
    void hUploadEnd(const Message&, Reader&);
    void hUploadAbort(const Message&, Reader&);
    void hDownloadBegin(const Message&, Reader&);
    void hDownloadChunk(const Message&, Reader&);
    void hDownloadEnd(const Message&, Reader&);
    void hHistory(const Message&, Reader&);
    void hUsersList(const Message&, Reader&);
    void hSetRole(const Message&, Reader&);
    void hDeleteUser(const Message&, Reader&);
    void hAudit(const Message&, Reader&);
    void hSysInfo(const Message&, Reader&);

    Services& svc_;
    int fd_;
    std::string addr_;
    TransferContext ctx_;
    bool sendOk_ = true;
    std::string user_;  // username after a successful login on this connection (for log lines)
};

}  // namespace linsft
