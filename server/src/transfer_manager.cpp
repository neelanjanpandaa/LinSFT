#include "linsft/transfer_manager.h"

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <ctime>

#include "linsft/logger.h"
#include "linsft/pathutil.h"

namespace linsft {

TransferContext::~TransferContext() { mgr.abortAll(*this, "connection closed"); }

void TransferManager::recoverStale() {
    try {
        int64_t n = db_.exec("UPDATE transfers SET status='FAILED',detail='server restarted',finished_at=? "
                             "WHERE status='IN_PROGRESS'", {int64_t(time(nullptr))});
        if (n > 0) LOG_WARN("marked %lld stale transfers as FAILED", (long long)n);
    } catch (const std::exception& e) {
        LOG_ERROR("recoverStale: %s", e.what());
    }
    DIR* d = ::opendir(fm_.tmpDir().c_str());
    if (!d) return;
    while (struct dirent* de = ::readdir(d)) {
        if (std::strncmp(de->d_name, "up-", 3) == 0) ::unlink((fm_.tmpDir() + "/" + de->d_name).c_str());
    }
    ::closedir(d);
}

void TransferManager::finishRow(int64_t id, const char* status, uint64_t size, const std::string& detail) {
    try {
        db_.exec("UPDATE transfers SET status=?,size=?,detail=?,finished_at=? WHERE id=?",
                 {std::string(status), int64_t(size), detail, int64_t(time(nullptr)), id});
    } catch (const std::exception& e) {
        LOG_ERROR("transfer history update failed: %s", e.what());
    }
}

Status TransferManager::beginUpload(TransferContext& ctx, const Principal& who, const std::string& vpath,
                                    uint64_t size, const std::string& sha, bool shared, bool overwrite,
                                    uint32_t& tid, std::string& msg) {
    if (ctx.uploads.size() + ctx.downloads.size() >= MAX_ACTIVE_PER_CONNECTION) {
        msg = "too many concurrent transfers on this connection";
        return Status::BUSY;
    }
    if (size > maxFileSize_) { msg = "file exceeds maximum size of " + std::to_string(maxFileSize_) + " bytes"; return Status::TOO_LARGE; }
    if (!isValidSha256Hex(sha)) { msg = "invalid checksum format"; return Status::BAD_REQUEST; }

    std::string rnd = randomHex(12);
    if (rnd.empty()) { msg = "entropy source unavailable"; return Status::INTERNAL; }
    UploadState up;
    up.tmpPath = fm_.tmpDir() + "/up-" + rnd;
    // O_EXCL + O_NOFOLLOW: never reuse or follow anything pre-existing in the staging directory
    up.fd = ::open(up.tmpPath.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0640);
    if (up.fd < 0) {
        LOG_ERROR("open staging file: %s", std::strerror(errno));
        msg = "cannot create staging file";
        return Status::IO_ERROR;
    }
    up.vpath = vpath; up.expectedSha = sha; up.expectedSize = size; up.shared = shared; up.overwrite = overwrite;
    try {
        up.transferId = db_.insert(
            "INSERT INTO transfers(user_id,username,direction,file_path,size,sha256,status,client_addr,started_at) "
            "VALUES(?,?,'UPLOAD',?,?,?,'IN_PROGRESS',?,?)",
            {who.userId, who.username, vpath, int64_t(size), sha, ctx.clientAddr, int64_t(time(nullptr))});

    } catch (const std::exception& e) {
        LOG_ERROR("transfer row insert: %s", e.what());
        ::close(up.fd);
        ::unlink(up.tmpPath.c_str());
        msg = "database error";
        return Status::INTERNAL;
    }
    tid = ctx.nextId++;
    ctx.uploads.emplace(tid, std::move(up));
    return Status::OK;
}

Status TransferManager::uploadChunk(TransferContext& ctx, uint32_t tid, const std::vector<uint8_t>& data,
                                    std::string& msg) {
    auto it = ctx.uploads.find(tid);
    if (it == ctx.uploads.end()) { msg = "unknown upload id"; return Status::NOT_FOUND; }
    UploadState& up = it->second;
    if (up.received + data.size() > up.expectedSize) {
        abortUpload(ctx, tid, "more data than announced");
        msg = "received more data than announced; upload aborted";
        return Status::BAD_REQUEST;
    }
    size_t off = 0;
    while (off < data.size()) {
        ssize_t w = ::write(up.fd, data.data() + off, data.size() - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            std::string why = std::string("write: ") + std::strerror(errno);
            LOG_ERROR("upload write failed: %s", why.c_str());
            abortUpload(ctx, tid, why);
            msg = "server write error";
            return Status::IO_ERROR;
        }
        off += size_t(w);
    }
    up.hasher.update(data.data(), data.size());
    up.received += data.size();
    stats_.bytesReceived += data.size();
    return Status::OK;
}

Status TransferManager::finishUpload(TransferContext& ctx, const Principal& who, uint32_t tid,
                                     std::string& msg, std::string& shaOut) {
    auto it = ctx.uploads.find(tid);
    if (it == ctx.uploads.end()) { msg = "unknown upload id"; return Status::NOT_FOUND; }
    UploadState up = std::move(it->second);
    ctx.uploads.erase(it);
    auto fail = [&](Status st, const std::string& m, const char* rowStatus) {
        if (up.fd >= 0) ::close(up.fd);
        ::unlink(up.tmpPath.c_str());
        finishRow(up.transferId, rowStatus, up.received, m);
        msg = m;
        return st;
    };
    if (up.received != up.expectedSize)
        return fail(Status::BAD_REQUEST, "incomplete upload: got " + std::to_string(up.received) + " of " +
                                          std::to_string(up.expectedSize) + " bytes", "FAILED");
    shaOut = toHex(up.hasher.finish());
    if (shaOut != up.expectedSha) {
        LOG_WARN("checksum mismatch on upload of %s by %s", up.vpath.c_str(), who.username.c_str());
        return fail(Status::CHECKSUM_MISMATCH, "SHA-256 mismatch: file corrupted in transit", "FAILED");
    }
    if (::fsync(up.fd) != 0) {
        std::string why = std::string("fsync: ") + std::strerror(errno);
        return fail(Status::IO_ERROR, why, "FAILED");
    }
    if (::close(up.fd) != 0) { up.fd = -1; return fail(Status::IO_ERROR, "close failed", "FAILED"); }
    up.fd = -1;
    FsResult fr = fm_.commitUpload(up.tmpPath, up.vpath, who.userId, up.received, shaOut, up.shared, up.overwrite);
    if (fr != FsResult::OK) {
        Status st = fr == FsResult::EXISTS ? Status::EXISTS : fr == FsResult::NOT_FOUND ? Status::NOT_FOUND
                  : fr == FsResult::NOT_A_DIR ? Status::INVALID_PATH : Status::INTERNAL;
        return fail(st, fsResultMessage(fr), "FAILED");
    }
    finishRow(up.transferId, "COMPLETED", up.received, "sha256 verified");
    stats_.uploadsCompleted++;
    msg = "upload complete";
    return Status::OK;
}

void TransferManager::abortUpload(TransferContext& ctx, uint32_t tid, const std::string& reason) {
    auto it = ctx.uploads.find(tid);
    if (it == ctx.uploads.end()) return;
    if (it->second.fd >= 0) ::close(it->second.fd);
    ::unlink(it->second.tmpPath.c_str());
    finishRow(it->second.transferId, "ABORTED", it->second.received, reason);
    ctx.uploads.erase(it);
}

Status TransferManager::beginDownload(TransferContext& ctx, const Principal& who, const FileEntry& file,
                                      uint32_t& tid, std::string& msg) {
    if (ctx.uploads.size() + ctx.downloads.size() >= MAX_ACTIVE_PER_CONNECTION) {
        msg = "too many concurrent transfers on this connection";
        return Status::BUSY;
    }
    DownloadState dl;
    dl.vpath = file.path;
    dl.fd = ::open(fm_.realPath(file.path).c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (dl.fd < 0) {
        LOG_ERROR("open %s: %s", fm_.realPath(file.path).c_str(), std::strerror(errno));
        msg = errno == ENOENT ? "file missing from storage" : "cannot open file";
        return errno == ENOENT ? Status::NOT_FOUND : Status::IO_ERROR;
    }
    struct stat st;
    if (::fstat(dl.fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        ::close(dl.fd);
        msg = "not a regular file";
        return Status::IO_ERROR;
    }
    if (uint64_t(st.st_size) != file.size) {
        LOG_WARN("size on disk (%lld) differs from database (%llu) for %s", (long long)st.st_size,
                 (unsigned long long)file.size, file.path.c_str());
    }
    dl.size = uint64_t(st.st_size);
    dl.sha = file.sha256;
    try {
        dl.transferId = db_.insert(
            "INSERT INTO transfers(user_id,username,direction,file_path,size,sha256,status,client_addr,started_at) "
            "VALUES(?,?,'DOWNLOAD',?,?,?,'IN_PROGRESS',?,?)",
            {who.userId, who.username, file.path, int64_t(dl.size), dl.sha, ctx.clientAddr, int64_t(time(nullptr))});

    } catch (const std::exception& e) {
        LOG_ERROR("transfer row insert: %s", e.what());
        ::close(dl.fd);
        msg = "database error";
        return Status::INTERNAL;
    }
    tid = ctx.nextId++;
    ctx.downloads.emplace(tid, std::move(dl));
    return Status::OK;
}

Status TransferManager::downloadChunk(TransferContext& ctx, uint32_t tid, std::vector<uint8_t>& out,
                                      bool& eof, std::string& msg) {
    auto it = ctx.downloads.find(tid);
    if (it == ctx.downloads.end()) { msg = "unknown download id"; return Status::NOT_FOUND; }
    DownloadState& dl = it->second;
    out.resize(CHUNK_SIZE);
    size_t got = 0;
    while (got < out.size()) {
        ssize_t r = ::read(dl.fd, out.data() + got, out.size() - got);
        if (r < 0) {
            if (errno == EINTR) continue;
            std::string why = std::string("read: ") + std::strerror(errno);
            LOG_ERROR("download read failed: %s", why.c_str());
            ::close(dl.fd);
            finishRow(dl.transferId, "FAILED", dl.sent, why);
            ctx.downloads.erase(it);
            msg = "server read error";
            return Status::IO_ERROR;
        }
        if (r == 0) break;
        got += size_t(r);
    }
    out.resize(got);
    dl.sent += got;
    eof = got < CHUNK_SIZE;
    stats_.bytesSent += got;
    return Status::OK;
}

Status TransferManager::finishDownload(TransferContext& ctx, uint32_t tid, bool clientVerified, std::string& msg) {
    auto it = ctx.downloads.find(tid);
    if (it == ctx.downloads.end()) { msg = "unknown download id"; return Status::NOT_FOUND; }
    DownloadState& dl = it->second;
    ::close(dl.fd);
    if (clientVerified && dl.sent == dl.size) {
        finishRow(dl.transferId, "COMPLETED", dl.sent, "client verified sha256");
        stats_.downloadsCompleted++;
    } else {
        finishRow(dl.transferId, "FAILED", dl.sent, clientVerified ? "incomplete" : "client reported checksum mismatch");
    }
    ctx.downloads.erase(it);
    msg = "download finished";
    return Status::OK;
}

void TransferManager::abortAll(TransferContext& ctx, const std::string& reason) {
    while (!ctx.uploads.empty()) abortUpload(ctx, ctx.uploads.begin()->first, reason);
    for (auto& kv : ctx.downloads) {
        ::close(kv.second.fd);
        finishRow(kv.second.transferId, "ABORTED", kv.second.sent, reason);
    }
    ctx.downloads.clear();
}

}  // namespace linsft
