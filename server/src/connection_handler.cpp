#include "linsft/connection_handler.h"

#include <sys/socket.h>

#include <algorithm>

#include "linsft/logger.h"
#include "linsft/pathutil.h"

namespace linsft {

using DB = DatabaseManager;

ConnectionHandler::ConnectionHandler(Services& svc, int fd, std::string addr)
    : svc_(svc), fd_(fd), addr_(std::move(addr)), ctx_(svc.transfers, addr_) {}

void ConnectionHandler::run() {
    Logger::instance().fileOnly("tcp connection opened: %s", addr_.c_str());
    svc_.stats.connectionsActive++;
    svc_.stats.connectionsTotal++;
    Message req;
    for (;;) {
        std::string err;
        IoResult r = recvMessage(fd_, req, err);
        if (r == IoResult::CLOSED) break;
        if (r == IoResult::TIMEOUT) { LOG_INFO("client %s idle timeout", addr_.c_str()); break; }
        if (r == IoResult::PROTOCOL) {
            svc_.stats.protocolErrors++;
            LOG_WARN("client %s protocol violation: %s; closing", addr_.c_str(), err.c_str());
            std::string e2;
            sendMessage(fd_, makeResponse(0, 0, Status::BAD_REQUEST, "protocol error: " + err), e2);
            // half-close, then drain unread bytes so close() sends FIN (not RST) and the client sees our reply
            ::shutdown(fd_, SHUT_WR);
            timeval tv{0, 200000};
            ::setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
            char sink[4096];
            for (int i = 0; i < 64 && ::recv(fd_, sink, sizeof sink, 0) > 0; ++i) {}
            break;
        }
        if (r == IoResult::ERROR) { LOG_WARN("client %s receive error: %s", addr_.c_str(), err.c_str()); break; }
        svc_.stats.requests++;
        if (!dispatch(req)) { LOG_WARN("client %s send failed; closing", addr_.c_str()); break; }
    }
    svc_.transfers.abortAll(ctx_, "connection closed");
    svc_.stats.connectionsActive--;
    if (!user_.empty()) Logger::instance().event("CLIENT", "%s disconnected (%s)", addr_.c_str(), user_.c_str());
    else Logger::instance().fileOnly("tcp connection closed: %s", addr_.c_str());
}

void ConnectionHandler::reply(const Message& req, Status st, const std::string& msg, const Writer* body) {
    std::string err;
    if (!sendMessage(fd_, makeResponse(req.type, req.requestId, st, msg, body), err)) {
        LOG_WARN("send to %s failed: %s", addr_.c_str(), err.c_str());
        sendOk_ = false;
    }
}

bool ConnectionHandler::authenticate(Reader& r, Session& s) {
    std::string token = r.str(128);
    return svc_.auth.validate(token, s);
}

void ConnectionHandler::audit(const Session& s, const char* action, const std::string& target,
                              const char* result, const std::string& detail, bool echo) {
    svc_.audit.record(s.userId, s.username, action, target, result, addr_, detail);
    if (!echo) return;
    std::string a = action, res = result;
    if (res == "DENIED") {
        Logger::instance().event("DENIED", "%s %s %s", s.username.c_str(), action, target.c_str());
        return;
    }
    std::string line = s.username + (a == "DOWNLOAD" ? " <- " : " -> ") + target + " " + res;
    if (res != "SUCCESS" && !detail.empty()) line += " (" + detail + ")";
    else if (res == "SUCCESS" && !detail.empty() && (a == "RENAME" || a == "SHARE" || a == "USER_SET_ROLE" || a == "USER_DELETE"))
        line += " " + detail;
    Logger::instance().event(action, "%s", line.c_str());
}

void ConnectionHandler::ensureHome(const std::string& username, int64_t userId) {
    svc_.files.ensureHomeDir(username, userId);
}

void ConnectionHandler::deny(const Message& m, const Session& s, const char* action, const std::string& target) {
    audit(s, action, target, "DENIED", "insufficient permission");
    reply(m, Status::FORBIDDEN, "permission denied");
}

bool ConnectionHandler::readPath(const Message& m, Reader& r, const Session* s, const char* action,
                                 std::string& out) {
    std::string raw = r.str(MAX_PATH_LEN + 64), err;
    if (!normalizeVirtualPath(raw, out, &err)) {
        svc_.audit.record(s ? s->userId : 0, s ? s->username : "", action, raw.substr(0, 200), "FAILURE", addr_,
                          "rejected path: " + err);
        reply(m, Status::INVALID_PATH, "invalid path: " + err);
        return false;
    }
    return true;
}

bool ConnectionHandler::dispatch(const Message& m) {
    sendOk_ = true;
    if ((m.type & RESPONSE_FLAG) || !isKnownMsgType(m.type)) {
        reply(m, Status::BAD_REQUEST, "unknown message type");
        return sendOk_;
    }
    try {
        Reader r(m.payload);
        switch (MsgType(m.type)) {
            case MsgType::PING: reply(m, Status::OK, "pong"); break;
            case MsgType::REGISTER: hRegister(m, r); break;
            case MsgType::LOGIN: hLogin(m, r); break;
            case MsgType::LOGOUT: hLogout(m, r); break;
            case MsgType::LIST: hList(m, r); break;
            case MsgType::SEARCH: hSearch(m, r); break;
            case MsgType::INFO: hInfo(m, r); break;
            case MsgType::RENAME: hRename(m, r); break;
            case MsgType::DELETE_FILE: hDelete(m, r); break;
            case MsgType::MKDIR: hMkdir(m, r); break;
            case MsgType::RMDIR: hRmdir(m, r); break;
            case MsgType::SHARE: hShare(m, r); break;
            case MsgType::UPLOAD_BEGIN: hUploadBegin(m, r); break;
            case MsgType::UPLOAD_CHUNK: hUploadChunk(m, r); break;
            case MsgType::UPLOAD_END: hUploadEnd(m, r); break;
            case MsgType::UPLOAD_ABORT: hUploadAbort(m, r); break;
            case MsgType::DOWNLOAD_BEGIN: hDownloadBegin(m, r); break;
            case MsgType::DOWNLOAD_CHUNK: hDownloadChunk(m, r); break;
            case MsgType::DOWNLOAD_END: hDownloadEnd(m, r); break;
            case MsgType::HISTORY: hHistory(m, r); break;
            case MsgType::USERS_LIST: hUsersList(m, r); break;
            case MsgType::USER_SET_ROLE: hSetRole(m, r); break;
            case MsgType::USER_DELETE: hDeleteUser(m, r); break;
            case MsgType::AUDIT: hAudit(m, r); break;
            case MsgType::SYSINFO: hSysInfo(m, r); break;
        }
    } catch (const ProtocolError& e) {
        svc_.stats.protocolErrors++;
        LOG_WARN("malformed %s from %s: %s", msgTypeName(m.type), addr_.c_str(), e.what());
        reply(m, Status::BAD_REQUEST, std::string("malformed request: ") + e.what());
    } catch (const DbError& e) {
        LOG_ERROR("database error in %s: %s", msgTypeName(m.type), e.what());
        reply(m, Status::INTERNAL, "database error");
    } catch (const std::exception& e) {
        LOG_ERROR("internal error in %s: %s", msgTypeName(m.type), e.what());
        reply(m, Status::INTERNAL, "internal error");
    }
    return sendOk_;
}

#define REQUIRE_AUTH(s)                                                   \
    Session s;                                                            \
    if (!authenticate(r, s)) { reply(m, Status::AUTH_REQUIRED, "login required or session expired"); return; }
#define REQUIRE_PERM(s, perm, action, target) \
    if (!PermissionService::has(s.principal(), perm)) { deny(m, s, action, target); return; }

// ---- authentication -----------------------------------------------------
void ConnectionHandler::hRegister(const Message& m, Reader& r) {
    std::string user = r.str(256), pass = r.str(1024);
    r.expectEnd();
    std::string msg;
    Status st = svc_.auth.registerUser(user, pass, msg);
    svc_.audit.record(0, user.substr(0, 64), "REGISTER", user.substr(0, 64), st == Status::OK ? "SUCCESS" : "FAILURE",
                      addr_, st == Status::OK ? "" : msg);
    if (st == Status::OK) {
        auto rows = svc_.db.query("SELECT id FROM users WHERE username=?", {user});
        if (!rows.empty()) ensureHome(user, DB::asInt(rows[0][0]));
    }
    reply(m, st, msg);
}

void ConnectionHandler::hLogin(const Message& m, Reader& r) {
    std::string user = r.str(256), pass = r.str(1024);
    r.expectEnd();
    Session s;
    std::string msg;
    Status st = svc_.auth.login(user, pass, s, msg);
    if (st != Status::OK) {
        svc_.audit.record(0, user.substr(0, 64), "LOGIN", user.substr(0, 64), "FAILURE", addr_, msg);
        Logger::instance().event("DENIED", "login failed for %s from %s (%s)", user.substr(0, 64).c_str(), addr_.c_str(), msg.c_str());
        reply(m, st, msg);
        return;
    }
    audit(s, "LOGIN", s.username, "SUCCESS", "", false);
    user_ = s.username;
    ensureHome(s.username, s.userId);
    Logger::instance().event("CLIENT", "%s connected (%s)", addr_.c_str(), s.username.c_str());
    Writer w;
    w.str(s.token).i64(s.userId).str(s.username).str(roleName(s.role));
    reply(m, Status::OK, msg, &w);
}

void ConnectionHandler::hLogout(const Message& m, Reader& r) {
    REQUIRE_AUTH(s);
    svc_.auth.logout(s.token);
    audit(s, "LOGOUT", s.username, "SUCCESS", "", false);
    Logger::instance().event("CLIENT", "%s logged out (%s)", addr_.c_str(), s.username.c_str());
    user_.clear();
    reply(m, Status::OK, "logged out");
}

// ---- browsing -----------------------------------------------------------
void ConnectionHandler::hList(const Message& m, Reader& r) {
    REQUIRE_AUTH(s);
    std::string path;
    if (!readPath(m, r, &s, "LIST", path)) return;
    r.expectEnd();
    REQUIRE_PERM(s, Perm::LIST, "LIST", path);
    auto dir = svc_.files.find(path);
    if (!dir) { reply(m, Status::NOT_FOUND, "no such directory"); return; }
    if (!dir->isDir) { reply(m, Status::INVALID_PATH, "not a directory"); return; }
    std::vector<FileEntry> out;
    for (auto& e : svc_.files.list(path))
        if (e.isDir || PermissionService::canReadFile(s.principal(), e.ownerId, e.shared)) out.push_back(std::move(e));
    Writer w;
    writeList(w, out);
    reply(m, Status::OK, "ok", &w);
}

void ConnectionHandler::hSearch(const Message& m, Reader& r) {
    REQUIRE_AUTH(s);
    std::string q = r.str(256);
    r.expectEnd();
    REQUIRE_PERM(s, Perm::SEARCH, "SEARCH", q);
    if (q.empty()) { reply(m, Status::BAD_REQUEST, "empty search query"); return; }
    std::vector<FileEntry> out;
    for (auto& e : svc_.files.search(q, 500))
        if (e.isDir || PermissionService::canReadFile(s.principal(), e.ownerId, e.shared)) out.push_back(std::move(e));
    std::string found = std::to_string(out.size()) + (out.size() == 1 ? " file found" : " files found");
    audit(s, "SEARCH", q.substr(0, 100), "SUCCESS", found, false);
    Logger::instance().event("SEARCH", "%s keyword: %s (%s)", s.username.c_str(), q.substr(0, 100).c_str(), found.c_str());
    Writer w;
    writeList(w, out);
    reply(m, Status::OK, "ok", &w);
}

void ConnectionHandler::hInfo(const Message& m, Reader& r) {
    REQUIRE_AUTH(s);
    std::string path;
    if (!readPath(m, r, &s, "INFO", path)) return;
    r.expectEnd();
    REQUIRE_PERM(s, Perm::INFO, "INFO", path);
    auto e = svc_.files.find(path);
    if (!e) { reply(m, Status::NOT_FOUND, "no such file or directory"); return; }
    if (!e->isDir && !PermissionService::canReadFile(s.principal(), e->ownerId, e->shared)) { deny(m, s, "INFO", path); return; }
    e->mode = svc_.files.statMode(path);
    Writer w;
    write(w, *e);
    reply(m, Status::OK, "ok", &w);
}

// ---- mutations ----------------------------------------------------------
void ConnectionHandler::hRename(const Message& m, Reader& r) {
    REQUIRE_AUTH(s);
    std::string path;
    if (!readPath(m, r, &s, "RENAME", path)) return;
    std::string newName = r.str(512), nerr;
    r.expectEnd();
    if (path == "/") { reply(m, Status::INVALID_PATH, "cannot rename root"); return; }
    if (!isValidName(newName, &nerr)) {
        audit(s, "RENAME", path, "FAILURE", "bad new name: " + nerr);
        reply(m, Status::INVALID_PATH, "invalid name: " + nerr);
        return;
    }
    auto e = svc_.files.find(path);
    if (!e) { reply(m, Status::NOT_FOUND, "no such file or directory"); return; }
    if (!PermissionService::canRename(s.principal(), e->ownerId)) { deny(m, s, "RENAME", path); return; }
    std::string newPath;
    FsResult fr = svc_.files.renameEntry(path, newName, newPath);
    if (fr != FsResult::OK) {
        audit(s, "RENAME", path, "FAILURE", fsResultMessage(fr));
        reply(m, fr == FsResult::EXISTS ? Status::EXISTS : fr == FsResult::NOT_FOUND ? Status::NOT_FOUND
                  : fr == FsResult::INVALID ? Status::INVALID_PATH : Status::INTERNAL, fsResultMessage(fr));
        return;
    }
    audit(s, "RENAME", path, "SUCCESS", "-> " + newPath);
    Writer w;
    w.str(newPath);
    reply(m, Status::OK, "renamed", &w);
}

void ConnectionHandler::hDelete(const Message& m, Reader& r) {
    REQUIRE_AUTH(s);
    std::string path;
    if (!readPath(m, r, &s, "DELETE", path)) return;
    r.expectEnd();
    auto e = svc_.files.find(path);
    if (!e) { reply(m, Status::NOT_FOUND, "no such file"); return; }
    if (e->isDir) { reply(m, Status::INVALID_PATH, "is a directory; use rmdir"); return; }
    if (!PermissionService::canDeleteFile(s.principal(), e->ownerId)) { deny(m, s, "DELETE", path); return; }
    FsResult fr = svc_.files.removeFile(path);
    if (fr != FsResult::OK) {
        audit(s, "DELETE", path, "FAILURE", fsResultMessage(fr));
        reply(m, fr == FsResult::NOT_FOUND ? Status::NOT_FOUND : Status::INTERNAL, fsResultMessage(fr));
        return;
    }
    audit(s, "DELETE", path, "SUCCESS");
    reply(m, Status::OK, "deleted");
}

void ConnectionHandler::hMkdir(const Message& m, Reader& r) {
    REQUIRE_AUTH(s);
    std::string path;
    if (!readPath(m, r, &s, "MKDIR", path)) return;
    r.expectEnd();
    REQUIRE_PERM(s, Perm::MKDIR, "MKDIR", path);
    if (!PermissionService::canWriteInto(s.principal(), parentOf(path))) { deny(m, s, "MKDIR", path); return; }
    FsResult fr = svc_.files.makeDir(path, s.userId);
    if (fr != FsResult::OK) {
        audit(s, "MKDIR", path, "FAILURE", fsResultMessage(fr));
        reply(m, fr == FsResult::EXISTS ? Status::EXISTS : fr == FsResult::NOT_FOUND ? Status::NOT_FOUND
                  : fr == FsResult::NOT_A_DIR ? Status::INVALID_PATH : Status::INTERNAL, fsResultMessage(fr));
        return;
    }
    audit(s, "MKDIR", path, "SUCCESS");
    reply(m, Status::OK, "directory created");
}

void ConnectionHandler::hRmdir(const Message& m, Reader& r) {
    REQUIRE_AUTH(s);
    std::string path;
    if (!readPath(m, r, &s, "RMDIR", path)) return;
    r.expectEnd();
    auto e = svc_.files.find(path);
    if (!e) { reply(m, Status::NOT_FOUND, "no such directory"); return; }
    if (!e->isDir || path == "/") { reply(m, Status::INVALID_PATH, "not a removable directory"); return; }
    if (!PermissionService::canRemoveDir(s.principal(), e->ownerId)) { deny(m, s, "RMDIR", path); return; }
    FsResult fr = svc_.files.removeDir(path);
    if (fr != FsResult::OK) {
        audit(s, "RMDIR", path, "FAILURE", fsResultMessage(fr));
        reply(m, fr == FsResult::NOT_EMPTY ? Status::NOT_EMPTY : fr == FsResult::NOT_FOUND ? Status::NOT_FOUND
                  : Status::INTERNAL, fsResultMessage(fr));
        return;
    }
    audit(s, "RMDIR", path, "SUCCESS");
    reply(m, Status::OK, "directory removed");
}

void ConnectionHandler::hShare(const Message& m, Reader& r) {
    REQUIRE_AUTH(s);
    std::string path;
    if (!readPath(m, r, &s, "SHARE", path)) return;
    bool shared = r.boolean();
    r.expectEnd();
    auto e = svc_.files.find(path);
    if (!e || e->isDir) { reply(m, Status::NOT_FOUND, "no such file"); return; }
    if (!PermissionService::canShare(s.principal(), e->ownerId)) { deny(m, s, "SHARE", path); return; }
    FsResult fr = svc_.files.setShared(path, shared);
    if (fr != FsResult::OK) { reply(m, Status::INTERNAL, fsResultMessage(fr)); return; }
    audit(s, "SHARE", path, "SUCCESS", shared ? "shared with everyone" : "made private");
    reply(m, Status::OK, shared ? "file is now shared" : "file is now private");
}

// ---- upload -------------------------------------------------------------
void ConnectionHandler::hUploadBegin(const Message& m, Reader& r) {
    REQUIRE_AUTH(s);
    std::string dir;
    if (!readPath(m, r, &s, "UPLOAD", dir)) return;
    std::string name = r.str(512), nerr;
    uint64_t size = r.u64();
    std::string sha = r.str(128);
    bool shared = r.boolean(), overwrite = r.boolean();
    r.expectEnd();
    REQUIRE_PERM(s, Perm::UPLOAD, "UPLOAD", dir);
    if (!PermissionService::canWriteInto(s.principal(), dir)) { deny(m, s, "UPLOAD", dir); return; }
    if (PermissionService::isPublicPath(dir)) shared = true;  // files in /public are readable by everyone
    if (!isValidName(name, &nerr)) {
        audit(s, "UPLOAD", dir + "/" + name.substr(0, 100), "FAILURE", "bad filename: " + nerr);
        reply(m, Status::INVALID_PATH, "invalid file name: " + nerr);
        return;
    }
    auto d = svc_.files.find(dir);
    if (!d) { reply(m, Status::NOT_FOUND, "target directory does not exist"); return; }
    if (!d->isDir) { reply(m, Status::INVALID_PATH, "target is not a directory"); return; }
    std::string vpath = joinPath(dir, name);
    if (auto ex = svc_.files.find(vpath)) {
        if (ex->isDir || !overwrite) { reply(m, Status::EXISTS, "a file or directory with that name already exists"); return; }
        if (!PermissionService::canDeleteFile(s.principal(), ex->ownerId)) { deny(m, s, "UPLOAD", vpath); return; }
    }
    uint32_t tid = 0;
    std::string msg;
    Status st = svc_.transfers.beginUpload(ctx_, s.principal(), vpath, size, sha, shared, overwrite, tid, msg);
    if (st != Status::OK) { audit(s, "UPLOAD", vpath, "FAILURE", msg); reply(m, st, msg); return; }
    Writer w;
    w.u32(tid).u32(uint32_t(CHUNK_SIZE));
    reply(m, Status::OK, "ready", &w);
}

void ConnectionHandler::hUploadChunk(const Message& m, Reader& r) {
    REQUIRE_AUTH(s);
    uint32_t tid = r.u32();
    std::vector<uint8_t> data = r.bytes(CHUNK_SIZE * 2);
    r.expectEnd();
    std::string msg;
    Status st = svc_.transfers.uploadChunk(ctx_, tid, data, msg);
    if (st != Status::OK) audit(s, "UPLOAD", "tid " + std::to_string(tid), "FAILURE", msg);
    reply(m, st, st == Status::OK ? "ok" : msg);
}

void ConnectionHandler::hUploadEnd(const Message& m, Reader& r) {
    REQUIRE_AUTH(s);
    uint32_t tid = r.u32();
    r.expectEnd();
    std::string target = "tid " + std::to_string(tid);
    uint64_t size = 0;
    auto it = ctx_.uploads.find(tid);
    if (it != ctx_.uploads.end()) { target = it->second.vpath; size = it->second.received; }
    std::string msg, sha;
    Status st = svc_.transfers.finishUpload(ctx_, s.principal(), tid, msg, sha);
    if (st == Status::OK) {
        audit(s, "UPLOAD", target, "SUCCESS", "sha256=" + sha, false);
        Logger::instance().event("UPLOAD", "%s -> %s (%s) SUCCESS", s.username.c_str(), target.c_str(), humanSize(size).c_str());
    } else {
        audit(s, "UPLOAD", target, "FAILURE", msg);
    }
    Writer w;
    w.str(sha);
    reply(m, st, msg, &w);
}

void ConnectionHandler::hUploadAbort(const Message& m, Reader& r) {
    REQUIRE_AUTH(s);
    uint32_t tid = r.u32();
    r.expectEnd();
    svc_.transfers.abortUpload(ctx_, tid, "aborted by client");
    audit(s, "UPLOAD", "tid " + std::to_string(tid), "FAILURE", "aborted by client");
    reply(m, Status::OK, "aborted");
}

// ---- download -----------------------------------------------------------
void ConnectionHandler::hDownloadBegin(const Message& m, Reader& r) {
    REQUIRE_AUTH(s);
    std::string path;
    if (!readPath(m, r, &s, "DOWNLOAD", path)) return;
    r.expectEnd();
    REQUIRE_PERM(s, Perm::DOWNLOAD, "DOWNLOAD", path);
    auto e = svc_.files.find(path);
    if (!e || e->isDir) { reply(m, Status::NOT_FOUND, "no such file"); return; }
    if (!PermissionService::canReadFile(s.principal(), e->ownerId, e->shared)) { deny(m, s, "DOWNLOAD", path); return; }
    uint32_t tid = 0;
    std::string msg;
    Status st = svc_.transfers.beginDownload(ctx_, s.principal(), *e, tid, msg);
    if (st != Status::OK) { audit(s, "DOWNLOAD", path, "FAILURE", msg); reply(m, st, msg); return; }
    Writer w;
    w.u32(tid).u64(e->size).str(e->sha256).str(e->name);
    reply(m, Status::OK, "ready", &w);
}

void ConnectionHandler::hDownloadChunk(const Message& m, Reader& r) {
    REQUIRE_AUTH(s);
    uint32_t tid = r.u32();
    r.expectEnd();
    std::vector<uint8_t> data;
    bool eof = false;
    std::string msg;
    Status st = svc_.transfers.downloadChunk(ctx_, tid, data, eof, msg);
    if (st != Status::OK) { audit(s, "DOWNLOAD", "tid " + std::to_string(tid), "FAILURE", msg); reply(m, st, msg); return; }
    Writer w;
    w.bytes(data.data(), data.size()).boolean(eof);
    reply(m, Status::OK, "ok", &w);
}

void ConnectionHandler::hDownloadEnd(const Message& m, Reader& r) {
    REQUIRE_AUTH(s);
    uint32_t tid = r.u32();
    bool ok = r.boolean();
    r.expectEnd();
    std::string target = "tid " + std::to_string(tid);
    uint64_t size = 0;
    auto it = ctx_.downloads.find(tid);
    if (it != ctx_.downloads.end()) { target = it->second.vpath; size = it->second.sent; }
    std::string msg;
    Status st = svc_.transfers.finishDownload(ctx_, tid, ok, msg);
    if (st == Status::OK) {
        if (ok) {
            audit(s, "DOWNLOAD", target, "SUCCESS", "", false);
            Logger::instance().event("DOWNLOAD", "%s <- %s (%s) SUCCESS", s.username.c_str(), target.c_str(), humanSize(size).c_str());
        } else {
            audit(s, "DOWNLOAD", target, "FAILURE", "client checksum mismatch");
        }
    }
    reply(m, st, msg);
}

// ---- history / admin ----------------------------------------------------
void ConnectionHandler::hHistory(const Message& m, Reader& r) {
    REQUIRE_AUTH(s);
    uint32_t limit = r.u32();
    r.expectEnd();
    limit = std::max<uint32_t>(1, std::min<uint32_t>(limit, 500));
    bool all = PermissionService::has(s.principal(), Perm::VIEW_ALL_HISTORY);
    if (!all && !PermissionService::has(s.principal(), Perm::VIEW_OWN_HISTORY)) { deny(m, s, "HISTORY", ""); return; }
    std::string sql = "SELECT id,user_id,username,direction,file_path,size,sha256,status,detail,client_addr,"
                      "started_at,finished_at FROM transfers ";
    std::vector<DB::Value> params;
    if (!all) { sql += "WHERE user_id=? "; params.emplace_back(s.userId); }
    sql += "ORDER BY id DESC LIMIT ?";
    params.emplace_back(int64_t(limit));
    std::vector<TransferEntry> out;
    for (auto& row : svc_.db.query(sql, params)) {
        TransferEntry e;
        e.id = DB::asInt(row[0]); e.userId = DB::asInt(row[1]); e.username = DB::asStr(row[2]);
        e.direction = DB::asStr(row[3]); e.path = DB::asStr(row[4]); e.size = uint64_t(DB::asInt(row[5]));
        e.sha256 = DB::asStr(row[6]); e.status = DB::asStr(row[7]); e.detail = DB::asStr(row[8]);
        e.clientAddr = DB::asStr(row[9]); e.started = DB::asInt(row[10]); e.finished = DB::asInt(row[11]);
        out.push_back(std::move(e));
    }
    Writer w;
    writeList(w, out);
    reply(m, Status::OK, "ok", &w);
}

void ConnectionHandler::hUsersList(const Message& m, Reader& r) {
    REQUIRE_AUTH(s);
    r.expectEnd();
    REQUIRE_PERM(s, Perm::MANAGE_USERS, "USERS_LIST", "");
    std::vector<UserEntry> out;
    for (auto& row : svc_.db.query("SELECT id,username,role,created_at,last_login FROM users ORDER BY id")) {
        UserEntry e;
        e.id = DB::asInt(row[0]); e.username = DB::asStr(row[1]); e.role = DB::asStr(row[2]);
        e.created = DB::asInt(row[3]); e.lastLogin = DB::asInt(row[4]);
        out.push_back(std::move(e));
    }
    Writer w;
    writeList(w, out);
    reply(m, Status::OK, "ok", &w);
}

void ConnectionHandler::hSetRole(const Message& m, Reader& r) {
    REQUIRE_AUTH(s);
    std::string user = r.str(256), roleStr = r.str(64);
    r.expectEnd();
    REQUIRE_PERM(s, Perm::MANAGE_USERS, "USER_SET_ROLE", user);
    Role role;
    if (!parseRole(roleStr, role)) { reply(m, Status::BAD_REQUEST, "invalid role (use STUDENT, FACULTY or ADMIN)"); return; }
    auto rows = svc_.db.query("SELECT id,role FROM users WHERE username=?", {user});
    if (rows.empty()) { reply(m, Status::NOT_FOUND, "no such user"); return; }
    int64_t uid = DB::asInt(rows[0][0]);
    if (DB::asStr(rows[0][1]) == "ADMIN" && role != Role::ADMIN) {
        auto cnt = svc_.db.query("SELECT COUNT(*) FROM users WHERE role='ADMIN'");
        if (DB::asInt(cnt[0][0]) <= 1) {
            audit(s, "USER_SET_ROLE", user, "FAILURE", "refused: last administrator");
            reply(m, Status::FORBIDDEN, "cannot demote the last administrator");
            return;
        }
    }
    svc_.db.exec("UPDATE users SET role=? WHERE id=?", {std::string(roleName(role)), uid});
    svc_.auth.onRoleChanged(uid, role);
    audit(s, "USER_SET_ROLE", user, "SUCCESS", std::string("role=") + roleName(role));
    reply(m, Status::OK, "role updated");
}

void ConnectionHandler::hDeleteUser(const Message& m, Reader& r) {
    REQUIRE_AUTH(s);
    std::string user = r.str(256);
    r.expectEnd();
    REQUIRE_PERM(s, Perm::MANAGE_USERS, "USER_DELETE", user);
    auto rows = svc_.db.query("SELECT id FROM users WHERE username=?", {user});
    if (rows.empty()) { reply(m, Status::NOT_FOUND, "no such user"); return; }
    int64_t uid = DB::asInt(rows[0][0]);
    if (uid == s.userId) { reply(m, Status::FORBIDDEN, "administrators cannot delete their own account"); return; }
    svc_.files.reassignOwner(uid, s.userId);  // keep the data, hand it to the acting admin
    svc_.db.exec("DELETE FROM users WHERE id=?", {uid});
    svc_.auth.invalidateUser(uid);
    audit(s, "USER_DELETE", user, "SUCCESS", "files reassigned to " + s.username);
    reply(m, Status::OK, "user deleted; their files were reassigned to you");
}

void ConnectionHandler::hAudit(const Message& m, Reader& r) {
    REQUIRE_AUTH(s);
    uint32_t limit = r.u32();
    r.expectEnd();
    REQUIRE_PERM(s, Perm::VIEW_AUDIT, "AUDIT", "");
    limit = std::max<uint32_t>(1, std::min<uint32_t>(limit, 1000));
    Writer w;
    writeList(w, svc_.audit.recent(limit));
    reply(m, Status::OK, "ok", &w);
}

void ConnectionHandler::hSysInfo(const Message& m, Reader& r) {
    REQUIRE_AUTH(s);
    r.expectEnd();
    REQUIRE_PERM(s, Perm::VIEW_SYSTEM, "SYSINFO", "");
    Writer w;
    writeKeyValues(w, svc_.sysmon.snapshot(svc_.auth.activeSessions()));
    reply(m, Status::OK, "ok", &w);
}

}  // namespace linsft
