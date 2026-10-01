#include "linsft/database.h"

#include <sqlite3.h>

#include <sys/stat.h>

#include "schema_embedded.h"

namespace linsft {

DatabaseManager::~DatabaseManager() { close(); }

bool DatabaseManager::open(const std::string& path, std::string& err) {
    std::lock_guard<std::recursive_mutex> lk(mu_);
    if (db_) return true;
    int rc = sqlite3_open_v2(path.c_str(), &db_,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nullptr);
    if (rc != SQLITE_OK) {
        err = std::string("sqlite3_open: ") + (db_ ? sqlite3_errmsg(db_) : sqlite3_errstr(rc));
        if (db_) { sqlite3_close(db_); db_ = nullptr; }
        return false;
    }
    ::chmod(path.c_str(), 0600);  // database holds password hashes: owner only
    sqlite3_busy_timeout(db_, 5000);
    char* msg = nullptr;
    const char* pragmas = "PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;";
    if (sqlite3_exec(db_, pragmas, nullptr, nullptr, &msg) != SQLITE_OK ||
        sqlite3_exec(db_, kSchemaSql, nullptr, nullptr, &msg) != SQLITE_OK) {
        err = std::string("schema init: ") + (msg ? msg : "unknown");
        sqlite3_free(msg);
        sqlite3_close(db_);
        db_ = nullptr;
        return false;
    }
    return true;
}

void DatabaseManager::close() {
    std::lock_guard<std::recursive_mutex> lk(mu_);
    if (db_) { sqlite3_close(db_); db_ = nullptr; }
}

namespace {
struct Stmt {
    sqlite3_stmt* s = nullptr;
    ~Stmt() { if (s) sqlite3_finalize(s); }
};
}  // namespace

static void bindAll(sqlite3* db, sqlite3_stmt* s, const std::vector<DatabaseManager::Value>& params) {
    for (size_t i = 0; i < params.size(); ++i) {
        int idx = int(i) + 1, rc;
        const auto& v = params[i];
        if (std::holds_alternative<std::nullptr_t>(v)) rc = sqlite3_bind_null(s, idx);
        else if (std::holds_alternative<int64_t>(v)) rc = sqlite3_bind_int64(s, idx, std::get<int64_t>(v));
        else {
            const std::string& str = std::get<std::string>(v);
            rc = sqlite3_bind_text(s, idx, str.data(), int(str.size()), SQLITE_TRANSIENT);
        }
        if (rc != SQLITE_OK) throw DbError(std::string("bind: ") + sqlite3_errmsg(db), rc);
    }
}

DatabaseManager::Rows DatabaseManager::query(const std::string& sql, const std::vector<Value>& params) {
    std::lock_guard<std::recursive_mutex> lk(mu_);
    if (!db_) throw DbError("database not open", SQLITE_MISUSE);
    Stmt st;
    int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, &st.s, nullptr);
    if (rc != SQLITE_OK) throw DbError(std::string("prepare: ") + sqlite3_errmsg(db_), rc);
    bindAll(db_, st.s, params);
    Rows rows;
    while ((rc = sqlite3_step(st.s)) == SQLITE_ROW) {
        Row row;
        int n = sqlite3_column_count(st.s);
        for (int c = 0; c < n; ++c) {
            switch (sqlite3_column_type(st.s, c)) {
                case SQLITE_INTEGER: row.emplace_back(int64_t(sqlite3_column_int64(st.s, c))); break;
                case SQLITE_NULL: row.emplace_back(nullptr); break;
                default: {
                    const unsigned char* t = sqlite3_column_text(st.s, c);
                    int len = sqlite3_column_bytes(st.s, c);
                    row.emplace_back(std::string(reinterpret_cast<const char*>(t ? t : (const unsigned char*)""), size_t(len)));
                }
            }
        }
        rows.push_back(std::move(row));
    }
    if (rc != SQLITE_DONE) throw DbError(std::string("step: ") + sqlite3_errmsg(db_), sqlite3_extended_errcode(db_));
    return rows;
}

int64_t DatabaseManager::exec(const std::string& sql, const std::vector<Value>& params) {
    std::lock_guard<std::recursive_mutex> lk(mu_);
    if (!db_) throw DbError("database not open", SQLITE_MISUSE);
    Stmt st;
    int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, &st.s, nullptr);
    if (rc != SQLITE_OK) throw DbError(std::string("prepare: ") + sqlite3_errmsg(db_), rc);
    bindAll(db_, st.s, params);
    rc = sqlite3_step(st.s);
    if (rc != SQLITE_DONE && rc != SQLITE_ROW)
        throw DbError(std::string("step: ") + sqlite3_errmsg(db_), sqlite3_extended_errcode(db_));
    return sqlite3_changes(db_);
}

int64_t DatabaseManager::insert(const std::string& sql, const std::vector<Value>& params) {
    std::lock_guard<std::recursive_mutex> lk(mu_);
    exec(sql, params);
    return sqlite3_last_insert_rowid(db_);
}

int64_t DatabaseManager::asInt(const Value& v) {
    if (std::holds_alternative<int64_t>(v)) return std::get<int64_t>(v);
    if (std::holds_alternative<std::string>(v)) return std::stoll(std::get<std::string>(v));
    return 0;
}
std::string DatabaseManager::asStr(const Value& v) {
    if (std::holds_alternative<std::string>(v)) return std::get<std::string>(v);
    if (std::holds_alternative<int64_t>(v)) return std::to_string(std::get<int64_t>(v));
    return std::string();
}

DatabaseManager::Transaction::Transaction(DatabaseManager& db) : db_(db), lock_(db.mu_) {
    db_.exec("BEGIN IMMEDIATE");
}
DatabaseManager::Transaction::~Transaction() {
    if (!done_) {
        try { db_.exec("ROLLBACK"); } catch (...) {}
    }
}
void DatabaseManager::Transaction::commit() {
    db_.exec("COMMIT");
    done_ = true;
}

}  // namespace linsft
