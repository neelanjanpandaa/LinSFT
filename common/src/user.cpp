#include "linsft/user.h"

namespace linsft {

bool Student::canDelete(int64_t ownerId) const {
    return ownerId == id_ && PermissionService::has(Role::STUDENT, Perm::DELETE_OWN);
}
bool Faculty::canDelete(int64_t ownerId) const {
    return ownerId == id_ && PermissionService::has(Role::FACULTY, Perm::DELETE_OWN);
}
bool Admin::canDelete(int64_t) const { return PermissionService::has(Role::ADMIN, Perm::DELETE_ANY); }

std::unique_ptr<User> User::create(const Principal& p) {
    switch (p.role) {
        case Role::ADMIN: return std::make_unique<Admin>(p.userId, p.username, p.role);
        case Role::FACULTY: return std::make_unique<Faculty>(p.userId, p.username, p.role);
        case Role::STUDENT: break;
    }
    return std::make_unique<Student>(p.userId, p.username, p.role);
}

}  // namespace linsft
