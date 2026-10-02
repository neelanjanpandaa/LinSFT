// Object-oriented user model: an abstract User with Student / Faculty / Admin specialisations.
// Each role decides for itself whether it may delete a resource (polymorphic canDelete()).
// The permission *table* still lives in PermissionService; these classes delegate to it so there
// is exactly one source of truth.
#pragma once
#include <cstdint>
#include <memory>
#include <string>

#include "linsft/permissions.h"

namespace linsft {

class User {
public:
    User(int64_t id, std::string username, Role role) : id_(id), username_(std::move(username)), role_(role) {}
    virtual ~User() = default;

    int64_t id() const { return id_; }
    const std::string& username() const { return username_; }
    Role role() const { return role_; }

    void login() { loggedIn_ = true; }
    void logout() { loggedIn_ = false; }
    bool isLoggedIn() const { return loggedIn_; }

    // May this user delete a file whose owner is ownerId?
    virtual bool canDelete(int64_t ownerId) const = 0;
    virtual const char* title() const = 0;

    static std::unique_ptr<User> create(const Principal& p);

protected:
    int64_t id_;
    std::string username_;
    Role role_;
    bool loggedIn_ = false;
};

class Student : public User {
public:
    using User::User;
    bool canDelete(int64_t ownerId) const override;
    const char* title() const override { return "Student"; }
};

class Faculty : public User {
public:
    using User::User;
    bool canDelete(int64_t ownerId) const override;
    const char* title() const override { return "Faculty"; }
};

class Admin : public User {
public:
    using User::User;
    bool canDelete(int64_t ownerId) const override;
    const char* title() const override { return "Admin"; }
};

}  // namespace linsft
