#include "linsft/permissions.h"

#include <strings.h>

#include "linsft/user.h"

namespace linsft {

const char* roleName(Role r) {
    switch (r) {
        case Role::STUDENT: return "STUDENT";
        case Role::FACULTY: return "FACULTY";
        case Role::ADMIN: return "ADMIN";
    }
    return "STUDENT";
}

bool parseRole(const std::string& s, Role& out) {
    if (s == "STUDENT") { out = Role::STUDENT; return true; }
    if (s == "FACULTY") { out = Role::FACULTY; return true; }
    if (s == "ADMIN") { out = Role::ADMIN; return true; }
    return false;
}

bool PermissionService::has(Role role, Perm perm) {
    switch (perm) {
        // every authenticated role
        case Perm::UPLOAD: case Perm::DOWNLOAD: case Perm::LIST: case Perm::SEARCH:
        case Perm::INFO: case Perm::RENAME_OWN: case Perm::DELETE_OWN: case Perm::SHARE_OWN:
        case Perm::MKDIR: case Perm::RMDIR_OWN: case Perm::VIEW_OWN_HISTORY:
            return true;
        // faculty and admin
        case Perm::READ_ALL_FILES: case Perm::VIEW_ALL_HISTORY: case Perm::VIEW_SYSTEM:
            return role == Role::FACULTY || role == Role::ADMIN;
        // admin only
        case Perm::RENAME_ANY: case Perm::DELETE_ANY: case Perm::RMDIR_ANY:
        case Perm::MANAGE_USERS: case Perm::VIEW_AUDIT:
            return role == Role::ADMIN;
    }
    return false;
}

bool PermissionService::canReadFile(const Principal& p, int64_t ownerId, bool shared) {
    return ownerId == p.userId || shared || has(p, Perm::READ_ALL_FILES);
}
bool PermissionService::canRename(const Principal& p, int64_t ownerId) {
    return (ownerId == p.userId && has(p, Perm::RENAME_OWN)) || has(p, Perm::RENAME_ANY);
}
bool PermissionService::canDeleteFile(const Principal& p, int64_t ownerId) {
    return User::create(p)->canDelete(ownerId);  // polymorphic: Student / Faculty / Admin
}
bool PermissionService::canShare(const Principal& p, int64_t ownerId) {
    return (ownerId == p.userId && has(p, Perm::SHARE_OWN)) || has(p, Perm::RENAME_ANY);
}
bool PermissionService::canRemoveDir(const Principal& p, int64_t ownerId) {
    return (ownerId == p.userId && has(p, Perm::RMDIR_OWN)) || has(p, Perm::RMDIR_ANY);
}

}  // namespace linsft

namespace linsft {

bool PermissionService::canWriteInto(const Principal& p, const std::string& dirPath) {
    if (has(p, Perm::MANAGE_USERS)) return true;  // admin
    if (dirPath == "/users") return false;
    const std::string prefix = "/users/";
    if (dirPath.compare(0, prefix.size(), prefix) != 0) return true;
    size_t end = dirPath.find('/', prefix.size());
    std::string owner = dirPath.substr(prefix.size(), end == std::string::npos ? std::string::npos : end - prefix.size());
    return strcasecmp(owner.c_str(), p.username.c_str()) == 0;
}

bool PermissionService::isPublicPath(const std::string& dirPath) {
    return dirPath == "/public" || dirPath.compare(0, 8, "/public/") == 0;
}

}  // namespace linsft
