// Thin RAII wrapper around SQLite. Every statement is prepared and parameter-bound.
#pragma once
#include <cstdint>
#include <mutex>
#include <stdexcept>
#include <string>
#include <variant>
#include <vector>

struct sqlite3;

namespace linsft {

class DbError : public std::runtime_error {
public:
    DbError(const std::string& m, int code) : std::runtime_error(m), code_(code) {}
    int code() const { return code_; }
    bool isConstraint() const { return (code_ & 0xff) == 19; }  // SQLITE_CONSTRAINT
private:
    int code_;
};

class DatabaseManager {
public:
    using Value = std::variant<std::nullptr_t, int64_t, std::string>;
    using Row = std::vector<Value>;
    using Rows = std::vector<Row>;

    DatabaseManager() = default;
    ~DatabaseManager();
    DatabaseManager(const DatabaseManager&) = delete;
    DatabaseManager& operator=(const DatabaseManager&) = delete;

    bool open(const std::string& path, std::string& err);  // opens and applies schema
    void close();
    bool isOpen() const { return db_ != nullptr; }

    Rows query(const std::string& sql, const std::vector<Value>& params = {});
    int64_t exec(const std::string& sql, const std::vector<Value>& params = {});  // rows changed
    // INSERT and return the new rowid under ONE lock acquisition (exec()+lastInsertId() would race).
    int64_t insert(const std::string& sql, const std::vector<Value>& params);

    // Holds the DB lock for a multi-statement unit of work. Rolls back unless commit() is called.
    class Transaction {
    public:
        explicit Transaction(DatabaseManager& db);
        ~Transaction();
        void commit();
    private:
        DatabaseManager& db_;
        std::unique_lock<std::recursive_mutex> lock_;
        bool done_ = false;
    };

    static int64_t asInt(const Value& v);
    static std::string asStr(const Value& v);

private:
    sqlite3* db_ = nullptr;
    std::recursive_mutex mu_;
};

}  // namespace linsft
