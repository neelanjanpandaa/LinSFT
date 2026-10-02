#include "linsft/pathutil.h"

#include <cctype>
#include <vector>

namespace linsft {

static void setErr(std::string* e, const char* m) { if (e) *e = m; }

bool isValidUsername(const std::string& u, std::string* err) {
    if (u.size() < 3 || u.size() > 32) { setErr(err, "username must be 3-32 characters"); return false; }
    if (!std::isalnum(static_cast<unsigned char>(u[0]))) { setErr(err, "username must start with a letter or digit"); return false; }
    for (unsigned char c : u) {
        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                  c == '_' || c == '.' || c == '-';
        if (!ok) { setErr(err, "username may only contain letters, digits, '_', '.', '-'"); return false; }
    }
    return true;
}

bool isValidPassword(const std::string& p, std::string* err) {
    if (p.size() < 8) { setErr(err, "password must be at least 8 characters"); return false; }
    if (p.size() > 128) { setErr(err, "password must be at most 128 characters"); return false; }
    for (unsigned char c : p)
        if (c < 0x20 || c == 0x7f) { setErr(err, "password contains control characters"); return false; }
    return true;
}

bool isValidSha256Hex(const std::string& s) {
    if (s.size() != 64) return false;
    for (unsigned char c : s)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    return true;
}

bool isValidName(const std::string& name, std::string* err) {
    if (name.empty()) { setErr(err, "name is empty"); return false; }
    if (name.size() > MAX_NAME_LEN) { setErr(err, "name too long"); return false; }
    if (name == "." || name == "..") { setErr(err, "reserved name"); return false; }
    if (name[0] == '.') { setErr(err, "names starting with '.' are not allowed"); return false; }
    if (name.back() == ' ') { setErr(err, "name must not end with a space"); return false; }
    for (unsigned char c : name) {
        if (c < 0x20 || c == 0x7f) { setErr(err, "name contains control characters"); return false; }
        if (c == '/' || c == '\\') { setErr(err, "name contains a path separator"); return false; }
    }
    return true;
}

bool normalizeVirtualPath(const std::string& in, std::string& out, std::string* err) {
    if (in.empty() || in[0] != '/') { setErr(err, "path must be absolute (start with '/')"); return false; }
    if (in.size() > MAX_PATH_LEN) { setErr(err, "path too long"); return false; }
    for (unsigned char c : in) {
        if (c < 0x20 || c == 0x7f) { setErr(err, "path contains control characters"); return false; }
        if (c == '\\') { setErr(err, "path contains a backslash"); return false; }
    }
    std::vector<std::string> parts;
    size_t i = 0;
    while (i <= in.size()) {
        size_t j = in.find('/', i);
        if (j == std::string::npos) j = in.size();
        std::string comp = in.substr(i, j - i);
        i = j + 1;
        if (comp.empty() || comp == ".") continue;
        if (comp == "..") { setErr(err, "'..' is not allowed in paths"); return false; }
        if (!isValidName(comp, err)) return false;
        parts.push_back(comp);
    }
    out.clear();
    if (parts.empty()) { out = "/"; return true; }
    for (auto& p : parts) { out += '/'; out += p; }
    return true;
}

std::string parentOf(const std::string& p) {
    if (p == "/") return "/";
    size_t pos = p.find_last_of('/');
    return pos == 0 ? "/" : p.substr(0, pos);
}
std::string baseName(const std::string& p) {
    if (p == "/") return "/";
    return p.substr(p.find_last_of('/') + 1);
}
std::string joinPath(const std::string& dir, const std::string& name) {
    return dir == "/" ? "/" + name : dir + "/" + name;
}

}  // namespace linsft
