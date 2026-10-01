// Central RBAC definitions. Every authorisation decision in the server goes through
// PermissionService; the GUI uses the same table only to hide controls the role lacks.
#pragma once
#include <cstdint>
#include <string>

namespace linsft {

enum class Role { STUDENT, FACULTY, ADMIN };

enum class Perm {
    UPLOAD,
    DOWNLOAD,
    LIST,
    SEARCH,
    INFO,
    RENAME_OWN,
    DELETE_OWN,
    SHARE_OWN,
    MKDIR,
    RMDIR_OWN,
    VIEW_OWN_HISTORY,
    READ_ALL_FILES,     // faculty+: read private files of other users
    VIEW_ALL_HISTORY,   // faculty+
    VIEW_SYSTEM,        // faculty+: system monitoring panel
    RENAME_ANY,         // admin
    DELETE_ANY,         // admin
    RMDIR_ANY,          // admin
    MANAGE_USERS,       // admin
    VIEW_AUDIT,         // admin
};

const char* roleName(Role r);
bool parseRole(const std::string& s, Role& out);

struct Principal {
    int64_t userId = 0;
    std::string username;
    Role role = Role::STUDENT;
};

class PermissionService {
public:
    static bool has(Role role, Perm perm);
    static bool has(const Principal& p, Perm perm) { return has(p.role, perm); }

    // Resource-level rules (ownership + role)
    static bool canReadFile(const Principal& p, int64_t ownerId, bool shared);
    static bool canRename(const Principal& p, int64_t ownerId);
    static bool canDeleteFile(const Principal& p, int64_t ownerId);
    static bool canShare(const Principal& p, int64_t ownerId);
    static bool canRemoveDir(const Principal& p, int64_t ownerId);
};

}  // namespace linsft
