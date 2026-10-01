// Registration, login, session tokens and brute-force lockout.
#pragma once
#include <ctime>
#include <map>
#include <mutex>
#include <string>

#include "linsft/database.h"
#include "linsft/permissions.h"
#include "linsft/protocol.h"

namespace linsft {

struct Session {
    std::string token;
    int64_t userId = 0;
    std::string username;
    Role role = Role::STUDENT;
    time_t expires = 0;
    Principal principal() const { return Principal{userId, username, role}; }
};

class AuthenticationManager {
public:
    AuthenticationManager(DatabaseManager& db, uint32_t pbkdf2Iterations, int sessionTtlSeconds);

    Status registerUser(const std::string& username, const std::string& password, std::string& msg);
    // Creates a user with an explicit role (admin bootstrap / seeding). Updates the password if it exists.
    Status createOrUpdateUser(const std::string& username, const std::string& password, Role role,
                              std::string& msg);
    Status login(const std::string& username, const std::string& password, Session& out, std::string& msg);
    bool validate(const std::string& token, Session& out);  // refreshes idle timeout
    void logout(const std::string& token);
    void onRoleChanged(int64_t userId, Role role);
    void invalidateUser(int64_t userId);
    size_t activeSessions();

private:
    std::string hashPassword(const std::string& pw, const std::string& saltHex, uint32_t iterations);
    bool lockedOut(const std::string& key, int& retryAfter);
    void noteFailure(const std::string& key);
    void clearFailures(const std::string& key);

    DatabaseManager& db_;
    uint32_t iterations_;
    int ttl_;
    std::mutex mu_;
    std::map<std::string, Session> sessions_;
    struct Fail { int count = 0; time_t until = 0; };
    std::map<std::string, Fail> fails_;
};

}  // namespace linsft
