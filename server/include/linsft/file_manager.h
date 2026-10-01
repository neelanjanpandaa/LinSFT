// Virtual filesystem over a real storage directory. Directories are real Linux directories,
// files are real files; ownership/sharing metadata lives in SQLite. Compound operations are
// serialised with an internal mutex so DB rows and on-disk state stay consistent.
#pragma once
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "linsft/database.h"
#include "linsft/models.h"

namespace linsft {

enum class FsResult { OK, NOT_FOUND, EXISTS, INVALID, NOT_EMPTY, IO_ERROR, DB_ERROR, NOT_A_DIR };
const char* fsResultMessage(FsResult r);

class FileManager {
public:
    FileManager(DatabaseManager& db, std::string storageRoot);

    bool init(std::string& err);  // creates storage root (0750) and .tmp staging dir
    const std::string& root() const { return root_; }
    std::string tmpDir() const { return root_ + "/.tmp"; }
    std::string realPath(const std::string& normalizedVirtual) const;

    std::optional<FileEntry> find(const std::string& vpath);  // file or directory ("/" is synthetic)
    std::vector<FileEntry> list(const std::string& dirPath);
    std::vector<FileEntry> search(const std::string& query, size_t limit);

    FsResult makeDir(const std::string& vpath, int64_t ownerId);
    FsResult removeDir(const std::string& vpath);
    FsResult renameEntry(const std::string& vpath, const std::string& newName, std::string& newPath);
    FsResult removeFile(const std::string& vpath);
    FsResult setShared(const std::string& vpath, bool shared);
    // Atomically publishes a fully received + verified staging file (rename(2) + DB upsert).
    FsResult commitUpload(const std::string& tmpPath, const std::string& vpath, int64_t ownerId,
                          uint64_t size, const std::string& sha256, bool shared, bool overwrite);
    void reassignOwner(int64_t fromUser, int64_t toUser);

private:
    std::optional<FileEntry> findLocked(const std::string& vpath);
    DatabaseManager& db_;
    std::string root_;
    std::mutex mu_;
};

}  // namespace linsft
