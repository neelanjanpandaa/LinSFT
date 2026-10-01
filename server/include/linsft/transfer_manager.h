// Chunked binary upload/download state machines. One TransferContext per client connection;
// all descriptors are closed and staging files removed when the context is destroyed.
#pragma once
#include <atomic>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "linsft/crypto.h"
#include "linsft/database.h"
#include "linsft/file_manager.h"
#include "linsft/permissions.h"
#include "linsft/protocol.h"

namespace linsft {

struct ServerStats {
    std::atomic<uint64_t> bytesReceived{0}, bytesSent{0};
    std::atomic<uint64_t> uploadsCompleted{0}, downloadsCompleted{0};
    std::atomic<uint64_t> connectionsTotal{0}, connectionsActive{0};
    std::atomic<uint64_t> requests{0}, protocolErrors{0};
};

struct UploadState {
    int fd = -1;
    std::string tmpPath, vpath, expectedSha;
    uint64_t expectedSize = 0, received = 0;
    Sha256 hasher;
    bool shared = false, overwrite = false;
    int64_t transferId = 0;
};

struct DownloadState {
    int fd = -1;
    std::string vpath, sha;
    uint64_t size = 0, sent = 0;
    int64_t transferId = 0;
};

class TransferManager;

struct TransferContext {
    TransferContext(TransferManager& tm, std::string addr) : mgr(tm), clientAddr(std::move(addr)) {}
    ~TransferContext();
    TransferContext(const TransferContext&) = delete;
    TransferContext& operator=(const TransferContext&) = delete;
    TransferManager& mgr;
    std::string clientAddr;
    uint32_t nextId = 1;
    std::map<uint32_t, UploadState> uploads;
    std::map<uint32_t, DownloadState> downloads;
};

class TransferManager {
public:
    static constexpr size_t MAX_ACTIVE_PER_CONNECTION = 8;

    TransferManager(DatabaseManager& db, FileManager& fm, ServerStats& stats, uint64_t maxFileSize)
        : db_(db), fm_(fm), stats_(stats), maxFileSize_(maxFileSize) {}

    void recoverStale();  // marks IN_PROGRESS rows from a previous run as FAILED, clears staging dir

    // Callers must already have authorised the operation (PermissionService).
    Status beginUpload(TransferContext& ctx, const Principal& who, const std::string& vpath, uint64_t size,
                       const std::string& sha, bool shared, bool overwrite, uint32_t& tid, std::string& msg);
    Status uploadChunk(TransferContext& ctx, uint32_t tid, const std::vector<uint8_t>& data, std::string& msg);
    Status finishUpload(TransferContext& ctx, const Principal& who, uint32_t tid, std::string& msg,
                        std::string& sha);
    void abortUpload(TransferContext& ctx, uint32_t tid, const std::string& reason);

    Status beginDownload(TransferContext& ctx, const Principal& who, const FileEntry& file, uint32_t& tid,
                         std::string& msg);
    Status downloadChunk(TransferContext& ctx, uint32_t tid, std::vector<uint8_t>& out, bool& eof,
                         std::string& msg);
    Status finishDownload(TransferContext& ctx, uint32_t tid, bool clientVerified, std::string& msg);

    void abortAll(TransferContext& ctx, const std::string& reason);
    uint64_t maxFileSize() const { return maxFileSize_; }

private:
    void finishRow(int64_t id, const char* status, uint64_t size, const std::string& detail);
    DatabaseManager& db_;
    FileManager& fm_;
    ServerStats& stats_;
    uint64_t maxFileSize_;
};

}  // namespace linsft
