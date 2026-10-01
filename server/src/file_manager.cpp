#include "linsft/file_manager.h"

#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ctime>

#include "linsft/logger.h"
#include "linsft/pathutil.h"

namespace linsft {

using V = DatabaseManager::Value;

const char* fsResultMessage(FsResult r) {
    switch (r) {
        case FsResult::OK: return "ok";
        case FsResult::NOT_FOUND: return "no such file or directory";
        case FsResult::EXISTS: return "already exists";
        case FsResult::INVALID: return "invalid name or operation";
        case FsResult::NOT_EMPTY: return "directory is not empty";
        case FsResult::IO_ERROR: return "filesystem error";
        case FsResult::DB_ERROR: return "database error";
        case FsResult::NOT_A_DIR: return "parent is not a directory";
    }
    return "error";
}

FileManager::FileManager(DatabaseManager& db, std::string root) : db_(db), root_(std::move(root)) {
    while (root_.size() > 1 && root_.back() == '/') root_.pop_back();
}

bool FileManager::init(std::string& err) {
    for (const std::string& d : {root_, tmpDir()}) {
        if (::mkdir(d.c_str(), 0750) != 0 && errno != EEXIST) {
            err = "mkdir " + d + ": " + std::strerror(errno);
            return false;
        }
        struct stat st;
        if (::stat(d.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) { err = d + " is not a directory"; return false; }
    }
    // remove leftovers from a previous crash
    return true;
}

std::string FileManager::realPath(const std::string& v) const { return v == "/" ? root_ : root_ + v; }

static FileEntry fileFromRow(const DatabaseManager::Row& r) {
    FileEntry e;
    e.id = DatabaseManager::asInt(r[0]); e.path = DatabaseManager::asStr(r[1]); e.name = DatabaseManager::asStr(r[2]);
    e.isDir = false; e.size = uint64_t(DatabaseManager::asInt(r[3])); e.ownerId = DatabaseManager::asInt(r[4]);
    e.owner = DatabaseManager::asStr(r[5]); e.sha256 = DatabaseManager::asStr(r[6]);
    e.shared = DatabaseManager::asInt(r[7]) != 0; e.created = DatabaseManager::asInt(r[8]);
    e.modified = DatabaseManager::asInt(r[9]);
    return e;
}
static FileEntry dirFromRow(const DatabaseManager::Row& r) {
    FileEntry e;
    e.id = DatabaseManager::asInt(r[0]); e.path = DatabaseManager::asStr(r[1]); e.name = DatabaseManager::asStr(r[2]);
    e.isDir = true; e.ownerId = DatabaseManager::asInt(r[3]); e.owner = DatabaseManager::asStr(r[4]);
    e.created = DatabaseManager::asInt(r[5]); e.modified = e.created; e.shared = true;
    return e;
}

static const char* kFileSel =
    "SELECT f.id,f.path,f.name,f.size,f.owner_id,COALESCE(u.username,'?'),f.sha256,f.shared,"
    "f.created_at,f.modified_at FROM files f LEFT JOIN users u ON u.id=f.owner_id ";
static const char* kDirSel =
    "SELECT d.id,d.path,d.name,d.owner_id,COALESCE(u.username,'?'),d.created_at "
    "FROM directories d LEFT JOIN users u ON u.id=d.owner_id ";

std::optional<FileEntry> FileManager::findLocked(const std::string& vpath) {
    if (vpath == "/") {
        FileEntry e;
        e.path = "/"; e.name = "/"; e.isDir = true; e.owner = "system"; e.shared = true;
        return e;
    }
    auto rows = db_.query(std::string(kFileSel) + "WHERE f.path=?", {vpath});
    if (!rows.empty()) return fileFromRow(rows[0]);
    rows = db_.query(std::string(kDirSel) + "WHERE d.path=?", {vpath});
    if (!rows.empty()) return dirFromRow(rows[0]);
    return std::nullopt;
}

std::optional<FileEntry> FileManager::find(const std::string& vpath) {
    std::lock_guard<std::mutex> lk(mu_);
    return findLocked(vpath);
}

std::vector<FileEntry> FileManager::list(const std::string& dir) {
    std::lock_guard<std::mutex> lk(mu_);
    std::vector<FileEntry> out;
    for (auto& r : db_.query(std::string(kDirSel) + "WHERE d.parent=? ORDER BY d.name COLLATE NOCASE", {dir}))
        out.push_back(dirFromRow(r));
    for (auto& r : db_.query(std::string(kFileSel) + "WHERE f.parent=? ORDER BY f.name COLLATE NOCASE", {dir}))
        out.push_back(fileFromRow(r));
    return out;
}

std::vector<FileEntry> FileManager::search(const std::string& q, size_t limit) {
    std::lock_guard<std::mutex> lk(mu_);
    std::vector<FileEntry> out;
    // instr(lower(),lower()) avoids LIKE wildcard injection entirely
    for (auto& r : db_.query(std::string(kDirSel) + "WHERE instr(lower(d.name),lower(?))>0 ORDER BY d.path LIMIT ?",
                             {q, int64_t(limit)}))
        out.push_back(dirFromRow(r));
    for (auto& r : db_.query(std::string(kFileSel) + "WHERE instr(lower(f.name),lower(?))>0 ORDER BY f.path LIMIT ?",
                             {q, int64_t(limit)}))
        out.push_back(fileFromRow(r));
    return out;
}

FsResult FileManager::makeDir(const std::string& vpath, int64_t ownerId) {
    if (vpath == "/") return FsResult::EXISTS;
    std::lock_guard<std::mutex> lk(mu_);
    std::string parent = parentOf(vpath);
    auto p = findLocked(parent);
    if (!p) return FsResult::NOT_FOUND;
    if (!p->isDir) return FsResult::NOT_A_DIR;
    if (findLocked(vpath)) return FsResult::EXISTS;
    try {
        DatabaseManager::Transaction tx(db_);
        db_.exec("INSERT INTO directories(path,name,parent,owner_id,created_at) VALUES(?,?,?,?,?)",
                 {vpath, baseName(vpath), parent, ownerId, int64_t(time(nullptr))});
        if (::mkdir(realPath(vpath).c_str(), 0750) != 0) {
            LOG_ERROR("mkdir %s: %s", realPath(vpath).c_str(), std::strerror(errno));
            return errno == EEXIST ? FsResult::EXISTS : FsResult::IO_ERROR;
        }
        tx.commit();
    } catch (const DbError& e) {
        LOG_ERROR("makeDir db: %s", e.what());
        ::rmdir(realPath(vpath).c_str());
        return e.isConstraint() ? FsResult::EXISTS : FsResult::DB_ERROR;
    }
    return FsResult::OK;
}

FsResult FileManager::removeDir(const std::string& vpath) {
    if (vpath == "/") return FsResult::INVALID;
    std::lock_guard<std::mutex> lk(mu_);
    auto e = findLocked(vpath);
    if (!e || !e->isDir) return FsResult::NOT_FOUND;
    try {
        if (!db_.query("SELECT 1 FROM directories WHERE parent=? LIMIT 1", {vpath}).empty() ||
            !db_.query("SELECT 1 FROM files WHERE parent=? LIMIT 1", {vpath}).empty())
            return FsResult::NOT_EMPTY;
        DatabaseManager::Transaction tx(db_);
        db_.exec("DELETE FROM directories WHERE path=?", {vpath});
        if (::rmdir(realPath(vpath).c_str()) != 0 && errno != ENOENT) {
            LOG_ERROR("rmdir %s: %s", realPath(vpath).c_str(), std::strerror(errno));
            return errno == ENOTEMPTY ? FsResult::NOT_EMPTY : FsResult::IO_ERROR;
        }
        tx.commit();
    } catch (const DbError& ex) {
        LOG_ERROR("removeDir db: %s", ex.what());
        return FsResult::DB_ERROR;
    }
    return FsResult::OK;
}

FsResult FileManager::renameEntry(const std::string& vpath, const std::string& newName, std::string& newPath) {
    if (vpath == "/" || !isValidName(newName)) return FsResult::INVALID;
    std::lock_guard<std::mutex> lk(mu_);
    auto e = findLocked(vpath);
    if (!e) return FsResult::NOT_FOUND;
    newPath = joinPath(parentOf(vpath), newName);
    if (newPath == vpath) return FsResult::OK;
    if (findLocked(newPath)) return FsResult::EXISTS;
    int64_t now = int64_t(time(nullptr));
    try {
        DatabaseManager::Transaction tx(db_);
        if (!e->isDir) {
            db_.exec("UPDATE files SET path=?,name=?,modified_at=? WHERE path=?", {newPath, newName, now, vpath});
        } else {
            std::string oldPrefix = vpath + "/";
            db_.exec("UPDATE directories SET path=?1,name=?2 WHERE path=?3", {newPath, newName, vpath});
            // descendants: replace the leading path component; length() counts characters, as does substr()
            db_.exec("UPDATE directories SET path=?1||substr(path,length(?2)),parent=?1||substr(parent,length(?3)+1) "
                     "WHERE substr(path,1,length(?2))=?2",
                     {newPath, oldPrefix, vpath});
            db_.exec("UPDATE files SET path=?1||substr(path,length(?2)),parent=?1||substr(parent,length(?3)+1) "
                     "WHERE substr(path,1,length(?2))=?2",
                     {newPath, oldPrefix, vpath});
            // a direct child's parent is exactly vpath -> newPath (handled by the substr above: parent==vpath)
        }
        if (::rename(realPath(vpath).c_str(), realPath(newPath).c_str()) != 0) {
            LOG_ERROR("rename %s -> %s: %s", vpath.c_str(), newPath.c_str(), std::strerror(errno));
            return FsResult::IO_ERROR;
        }
        tx.commit();
    } catch (const DbError& ex) {
        LOG_ERROR("renameEntry db: %s", ex.what());
        return ex.isConstraint() ? FsResult::EXISTS : FsResult::DB_ERROR;
    }
    return FsResult::OK;
}

FsResult FileManager::removeFile(const std::string& vpath) {
    std::lock_guard<std::mutex> lk(mu_);
    auto e = findLocked(vpath);
    if (!e || e->isDir) return FsResult::NOT_FOUND;
    try {
        DatabaseManager::Transaction tx(db_);
        db_.exec("DELETE FROM files WHERE path=?", {vpath});
        if (::unlink(realPath(vpath).c_str()) != 0 && errno != ENOENT) {
            LOG_ERROR("unlink %s: %s", realPath(vpath).c_str(), std::strerror(errno));
            return FsResult::IO_ERROR;
        }
        tx.commit();
    } catch (const DbError& ex) {
        LOG_ERROR("removeFile db: %s", ex.what());
        return FsResult::DB_ERROR;
    }
    return FsResult::OK;
}

FsResult FileManager::setShared(const std::string& vpath, bool shared) {
    std::lock_guard<std::mutex> lk(mu_);
    auto e = findLocked(vpath);
    if (!e || e->isDir) return FsResult::NOT_FOUND;
    try {
        db_.exec("UPDATE files SET shared=?,modified_at=? WHERE path=?",
                 {int64_t(shared ? 1 : 0), int64_t(time(nullptr)), vpath});
    } catch (const DbError& ex) {
        LOG_ERROR("setShared db: %s", ex.what());
        return FsResult::DB_ERROR;
    }
    return FsResult::OK;
}

FsResult FileManager::commitUpload(const std::string& tmpPath, const std::string& vpath, int64_t ownerId,
                                   uint64_t size, const std::string& sha, bool shared, bool overwrite) {
    std::lock_guard<std::mutex> lk(mu_);
    auto parent = findLocked(parentOf(vpath));
    if (!parent) return FsResult::NOT_FOUND;
    if (!parent->isDir) return FsResult::NOT_A_DIR;
    auto existing = findLocked(vpath);
    if (existing && (existing->isDir || !overwrite)) return FsResult::EXISTS;
    int64_t now = int64_t(time(nullptr));
    try {
        DatabaseManager::Transaction tx(db_);
        if (existing) {
            db_.exec("UPDATE files SET size=?,sha256=?,shared=?,modified_at=? WHERE path=?",
                     {int64_t(size), sha, int64_t(shared ? 1 : 0), now, vpath});
        } else {
            db_.exec("INSERT INTO files(path,name,parent,owner_id,size,sha256,shared,created_at,modified_at) "
                     "VALUES(?,?,?,?,?,?,?,?,?)",
                     {vpath, baseName(vpath), parentOf(vpath), ownerId, int64_t(size), sha,
                      int64_t(shared ? 1 : 0), now, now});
        }
        if (::rename(tmpPath.c_str(), realPath(vpath).c_str()) != 0) {
            LOG_ERROR("rename staging -> %s: %s", realPath(vpath).c_str(), std::strerror(errno));
            return FsResult::IO_ERROR;
        }
        tx.commit();
    } catch (const DbError& ex) {
        LOG_ERROR("commitUpload db: %s", ex.what());
        return ex.isConstraint() ? FsResult::EXISTS : FsResult::DB_ERROR;
    }
    return FsResult::OK;
}

void FileManager::reassignOwner(int64_t from, int64_t to) {
    std::lock_guard<std::mutex> lk(mu_);
    db_.exec("UPDATE files SET owner_id=? WHERE owner_id=?", {to, from});
    db_.exec("UPDATE directories SET owner_id=? WHERE owner_id=?", {to, from});
}

}  // namespace linsft
