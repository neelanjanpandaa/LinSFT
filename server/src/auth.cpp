#include "linsft/auth.h"

#include <algorithm>
#include <cctype>

#include "linsft/crypto.h"
#include "linsft/logger.h"
#include "linsft/pathutil.h"

namespace linsft {

static constexpr int kMaxFailures = 5;
static constexpr int kLockSeconds = 60;

AuthenticationManager::AuthenticationManager(DatabaseManager& db, uint32_t it, int ttl)
    : db_(db), iterations_(it), ttl_(ttl) {}

static std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return char(std::tolower(c)); });
    return s;
}

std::string AuthenticationManager::hashPassword(const std::string& pw, const std::string& saltHex,
                                                uint32_t iterations) {
    std::vector<uint8_t> salt;
    fromHex(saltHex, salt);
    auto dk = pbkdf2HmacSha256(pw, salt.data(), salt.size(), iterations, 32);
    return toHex(dk.data(), dk.size());
}

Status AuthenticationManager::registerUser(const std::string& username, const std::string& password,
                                           std::string& msg) {
    if (!isValidUsername(username, &msg)) return Status::BAD_REQUEST;
    if (!isValidPassword(password, &msg)) return Status::BAD_REQUEST;
    std::string salt = randomHex(16);
    if (salt.empty()) { msg = "entropy source unavailable"; return Status::INTERNAL; }
    std::string hash = hashPassword(password, salt, iterations_);
    try {
        db_.exec("INSERT INTO users(username,salt,pw_hash,iterations,role,created_at) VALUES(?,?,?,?,?,?)",
                 {username, salt, hash, int64_t(iterations_), std::string("STUDENT"), int64_t(time(nullptr))});
    } catch (const DbError& e) {
        if (e.isConstraint()) { msg = "username already taken"; return Status::EXISTS; }
        LOG_ERROR("register: %s", e.what());
        msg = "database error";
        return Status::INTERNAL;
    }
    msg = "registered";
    return Status::OK;
}

Status AuthenticationManager::createOrUpdateUser(const std::string& username, const std::string& password,
                                                 Role role, std::string& msg) {
    if (!isValidUsername(username, &msg)) return Status::BAD_REQUEST;
    if (!isValidPassword(password, &msg)) return Status::BAD_REQUEST;
    std::string salt = randomHex(16);
    if (salt.empty()) { msg = "entropy source unavailable"; return Status::INTERNAL; }
    std::string hash = hashPassword(password, salt, iterations_);
    try {
        auto rows = db_.query("SELECT id FROM users WHERE username=?", {username});
        if (rows.empty()) {
            db_.exec("INSERT INTO users(username,salt,pw_hash,iterations,role,created_at) VALUES(?,?,?,?,?,?)",
                     {username, salt, hash, int64_t(iterations_), std::string(roleName(role)),
                      int64_t(time(nullptr))});
            msg = "created";
        } else {
            int64_t id = DatabaseManager::asInt(rows[0][0]);
            db_.exec("UPDATE users SET salt=?,pw_hash=?,iterations=?,role=? WHERE id=?",
                     {salt, hash, int64_t(iterations_), std::string(roleName(role)), id});
            invalidateUser(id);
            msg = "updated";
        }
    } catch (const DbError& e) {
        LOG_ERROR("createOrUpdateUser: %s", e.what());
        msg = "database error";
        return Status::INTERNAL;
    }
    return Status::OK;
}

bool AuthenticationManager::lockedOut(const std::string& key, int& retryAfter) {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = fails_.find(key);
    if (it == fails_.end()) return false;
    time_t now = time(nullptr);
    if (it->second.until > now) { retryAfter = int(it->second.until - now); return true; }
    return false;
}
void AuthenticationManager::noteFailure(const std::string& key) {
    std::lock_guard<std::mutex> lk(mu_);
    Fail& f = fails_[key];
    if (f.until != 0 && f.until <= time(nullptr)) { f.count = 0; f.until = 0; }
    if (++f.count >= kMaxFailures) { f.until = time(nullptr) + kLockSeconds; f.count = 0; }
}
void AuthenticationManager::clearFailures(const std::string& key) {
    std::lock_guard<std::mutex> lk(mu_);
    fails_.erase(key);
}

Status AuthenticationManager::login(const std::string& username, const std::string& password,
                                    Session& out, std::string& msg) {
    std::string key = lower(username);
    int retry = 0;
    if (lockedOut(key, retry)) {
        msg = "too many failed attempts; retry in " + std::to_string(retry) + "s";
        return Status::LOCKED_OUT;
    }
    if (username.empty() || username.size() > 64 || password.size() > 1024) {
        msg = "invalid credentials";
        return Status::AUTH_FAILED;
    }
    try {
        auto rows = db_.query("SELECT id,username,salt,pw_hash,iterations,role FROM users WHERE username=?",
                              {username});
        if (rows.empty()) {
            // burn comparable CPU so response time does not reveal whether the account exists
            hashPassword(password, "00112233445566778899aabbccddeeff", iterations_);
            noteFailure(key);
            msg = "invalid credentials";
            return Status::AUTH_FAILED;
        }
        const auto& r = rows[0];
        std::string calc = hashPassword(password, DatabaseManager::asStr(r[2]),
                                        uint32_t(DatabaseManager::asInt(r[4])));
        if (!constantTimeEquals(calc, DatabaseManager::asStr(r[3]))) {
            noteFailure(key);
            msg = "invalid credentials";
            return Status::AUTH_FAILED;
        }
        Role role;
        if (!parseRole(DatabaseManager::asStr(r[5]), role)) {
            msg = "account has an invalid role";
            return Status::INTERNAL;
        }
        clearFailures(key);
        Session s;
        s.token = randomHex(32);
        if (s.token.empty()) { msg = "entropy source unavailable"; return Status::INTERNAL; }
        s.userId = DatabaseManager::asInt(r[0]);
        s.username = DatabaseManager::asStr(r[1]);
        s.role = role;
        s.expires = time(nullptr) + ttl_;
        db_.exec("UPDATE users SET last_login=? WHERE id=?", {int64_t(time(nullptr)), s.userId});
        {
            std::lock_guard<std::mutex> lk(mu_);
            sessions_[s.token] = s;
        }
        out = s;
        msg = "login ok";
        return Status::OK;
    } catch (const DbError& e) {
        LOG_ERROR("login: %s", e.what());
        msg = "database error";
        return Status::INTERNAL;
    }
}

bool AuthenticationManager::validate(const std::string& token, Session& out) {
    if (token.size() != 64) return false;
    std::lock_guard<std::mutex> lk(mu_);
    auto it = sessions_.find(token);
    if (it == sessions_.end()) return false;
    time_t now = time(nullptr);
    if (it->second.expires < now) { sessions_.erase(it); return false; }
    it->second.expires = now + ttl_;
    out = it->second;
    return true;
}

void AuthenticationManager::logout(const std::string& token) {
    std::lock_guard<std::mutex> lk(mu_);
    sessions_.erase(token);
}

void AuthenticationManager::onRoleChanged(int64_t userId, Role role) {
    std::lock_guard<std::mutex> lk(mu_);
    for (auto& kv : sessions_)
        if (kv.second.userId == userId) kv.second.role = role;
}

void AuthenticationManager::invalidateUser(int64_t userId) {
    std::lock_guard<std::mutex> lk(mu_);
    for (auto it = sessions_.begin(); it != sessions_.end();) {
        if (it->second.userId == userId) it = sessions_.erase(it);
        else ++it;
    }
}

size_t AuthenticationManager::activeSessions() {
    std::lock_guard<std::mutex> lk(mu_);
    return sessions_.size();
}

}  // namespace linsft
