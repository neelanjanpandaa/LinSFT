// Input validation and virtual-path handling. All client supplied names/paths pass through here.
#pragma once
#include <string>

namespace linsft {

constexpr size_t MAX_PATH_LEN = 1024;
constexpr size_t MAX_NAME_LEN = 255;

bool isValidUsername(const std::string& u, std::string* err = nullptr);
bool isValidPassword(const std::string& p, std::string* err = nullptr);
bool isValidSha256Hex(const std::string& s);

// A single path component (file or directory name).
bool isValidName(const std::string& name, std::string* err = nullptr);

// Canonicalises a virtual path ("/a//b/./c" -> "/a/b/c"). Rejects relative paths, "..",
// backslashes, NUL/control characters, over-long paths and invalid components.
bool normalizeVirtualPath(const std::string& in, std::string& out, std::string* err = nullptr);

std::string parentOf(const std::string& normalized);   // "/a/b" -> "/a", "/a" -> "/"
std::string baseName(const std::string& normalized);   // "/a/b" -> "b"
std::string joinPath(const std::string& dir, const std::string& name);

}  // namespace linsft
