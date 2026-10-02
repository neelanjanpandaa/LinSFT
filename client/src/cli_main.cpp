// network-file-client (alias: file_client): interactive / scriptable command line client for LinSFT.
//   ./file_client 127.0.0.1 5000
#include <termios.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <sstream>

#include "linsft/client.h"
#include "linsft/pathutil.h"

using namespace linsft;

static std::string g_cwd = "/";

static std::string resolve(const std::string& arg) {
    std::string p = arg.empty() ? g_cwd : (arg[0] == '/' ? arg : (g_cwd == "/" ? "/" + arg : g_cwd + "/" + arg));
    // collapse ".." client-side for navigation convenience; the server re-validates everything
    std::vector<std::string> parts;
    std::stringstream ss(p);
    std::string c;
    while (std::getline(ss, c, '/')) {
        if (c.empty() || c == ".") continue;
        if (c == "..") { if (!parts.empty()) parts.pop_back(); continue; }
        parts.push_back(c);
    }
    std::string out;
    for (auto& s : parts) out += "/" + s;
    return out.empty() ? "/" : out;
}

static std::vector<std::string> tokenize(const std::string& line) {
    std::vector<std::string> t;
    std::string cur;
    bool inQ = false, have = false;
    char q = 0;
    for (char ch : line) {
        if (inQ) { if (ch == q) inQ = false; else cur += ch; }
        else if (ch == '"' || ch == '\'') { inQ = true; q = ch; have = true; }
        else if (ch == ' ' || ch == '\t') { if (have || !cur.empty()) { t.push_back(cur); cur.clear(); have = false; } }
        else cur += ch;
    }
    if (have || !cur.empty()) t.push_back(cur);
    return t;
}

// Password prompt: echoes '*' per character on a terminal; plain getline when input is piped.
static std::string readSecret(const std::string& prompt) {
    std::cout << prompt << std::flush;
    std::string s;
    if (!isatty(STDIN_FILENO)) { std::getline(std::cin, s); return s; }
    termios oldt{};
    tcgetattr(STDIN_FILENO, &oldt);
    termios nt = oldt;
    nt.c_lflag &= ~tcflag_t(ECHO | ICANON);
    nt.c_cc[VMIN] = 1;
    nt.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSANOW, &nt);
    for (;;) {
        char ch;
        ssize_t n = ::read(STDIN_FILENO, &ch, 1);
        if (n <= 0 || ch == '\n' || ch == '\r') break;
        if (ch == 127 || ch == 8) { if (!s.empty()) { s.pop_back(); std::cout << "\b \b" << std::flush; } }
        else if (ch == 4 && s.empty()) break;
        else if (static_cast<unsigned char>(ch) >= 0x20) { s += ch; std::cout << '*' << std::flush; }
    }
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    std::cout << "\n";
    return s;
}

static void show(const Result& r, const char* okMsg = nullptr) {
    if (r.ok) std::cout << (okMsg ? okMsg : r.message.c_str()) << "\n";
    else std::cout << "ERROR [" << statusName(r.status) << "]: " << r.message << "\n";
}

// Detailed table (ls -l / search results)
static void printTable(const std::vector<FileEntry>& v, bool withPath) {
    if (v.empty()) { std::cout << "(empty)\n"; return; }
    printf("%-4s %-10s %-10s %-7s %-19s %s\n", "TYPE", "SIZE", "OWNER", "SHARED", "MODIFIED", "NAME");
    for (auto& e : v)
        printf("%-4s %-10s %-10s %-7s %-19s %s\n", e.isDir ? "dir" : "file", e.isDir ? "-" : humanSize(e.size).c_str(),
               e.owner.c_str(), e.isDir ? "-" : (e.shared ? "yes" : "no"), formatTime(e.modified).c_str(),
               (withPath ? e.path : e.name + (e.isDir ? "/" : "")).c_str());
}

// Compact numbered listing
static void printListing(const std::vector<FileEntry>& v) {
    std::cout << "Server files:\n";
    if (v.empty()) { std::cout << "  (empty)\n"; return; }
    int i = 1;
    for (auto& e : v)
        printf("%2d. %-30s %s\n", i++, (e.name + (e.isDir ? "/" : "")).c_str(), e.isDir ? "<DIR>" : humanSize(e.size).c_str());
}

static void help() {
    std::puts(
        "Commands (case-insensitive):\n"
        "  REGISTER <user>            create a STUDENT account\n"
        "  LOGIN <user> | LOGOUT | WHOAMI\n"
        "  LIST [path] [-l]  CD <path>  PWD  SEARCH <text>  INFO <path>\n"
        "  UPLOAD <local file> [remote dir] [--shared] [--overwrite]\n"
        "  DOWNLOAD <remote file> [local path] [--overwrite]\n"
        "  RENAME <path> <new name>   DELETE <file>   MKDIR <path>   RMDIR <path>\n"
        "  SHARE <file>  UNSHARE <file>\n"
        "  HISTORY [n]\n"
        "  SYSINFO                    (FACULTY/ADMIN)\n"
        "  USERS | SETROLE <user> <STUDENT|FACULTY|ADMIN> | DELUSER <user> | AUDIT [n]   (ADMIN)\n"
        "  HELP  QUIT");
}

static bool flag(std::vector<std::string>& a, const std::string& f) {
    for (size_t i = 0; i < a.size(); ++i) if (a[i] == f) { a.erase(a.begin() + long(i)); return true; }
    return false;
}

static std::string lowerStr(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return char(std::tolower(c)); });
    return s;
}

int main(int argc, char** argv) {
    std::string host = "127.0.0.1";
    uint16_t port = 5000;
    bool forcePrompt = false;
    std::vector<std::string> positional;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if ((a == "--host" || a == "-H") && i + 1 < argc) host = argv[++i];
        else if ((a == "--port" || a == "-p") && i + 1 < argc) port = uint16_t(std::atoi(argv[++i]));
        else if (a == "--prompt-login") forcePrompt = true;
        else if (a == "--help" || a == "-h") {
            std::puts("Usage: network-file-client [HOST [PORT]] [--host HOST] [--port PORT]\n"
                      "  e.g.  ./file_client 127.0.0.1 5000\n"
                      "Prompts for Username/Password, then reads commands (terminal or stdin). Type HELP inside.");
            return 0;
        } else if (!a.empty() && a[0] != '-') positional.push_back(a);
        else { std::cerr << "unknown option " << a << "\n"; return 2; }
    }
    if (positional.size() > 2) { std::cerr << "too many arguments\n"; return 2; }
    if (!positional.empty()) host = positional[0];
    if (positional.size() == 2) port = uint16_t(std::atoi(positional[1].c_str()));

    Client c;
    Result cr = c.connectTo(host, port);
    if (!cr.ok) { std::cerr << "ERROR: " << cr.message << "\n(Is the server running? e.g. ./file_server " << port << ")\n"; return 1; }
    bool interactive = isatty(STDIN_FILENO);
    std::cout << "Connected to server " << host << ":" << port << "\n";

    // Poster-style start-up login: Username / Password / "Login successful! Role: X"
    if (interactive || forcePrompt) {
        std::cout << "Username (blank = skip, use REGISTER/LOGIN later): " << std::flush;
        std::string user;
        std::getline(std::cin, user);
        if (!user.empty()) {
            Result r = c.login(user, readSecret("Password: "));
            if (r.ok) std::cout << "Login successful! Role: " << roleName(c.role()) << "\n";
            else show(r);
        }
    }
    std::cout << "\nType 'help' to see available commands.\n";

    std::string line;
    int exitCode = 0;
    for (;;) {
        if (interactive) std::cout << (c.loggedIn() ? "File" : "linsft") << (g_cwd == "/" ? "" : ":" + g_cwd) << "> " << std::flush;
        if (!std::getline(std::cin, line)) break;
        auto t = tokenize(line);
        if (t.empty() || t[0][0] == '#') continue;
        std::string cmd = lowerStr(t[0]);
        if (cmd == "list" || cmd == "dir") cmd = "ls";
        if (cmd == "delete" || cmd == "del") cmd = "rm";
        std::vector<std::string> a(t.begin() + 1, t.end());
        if (!interactive) std::cout << "> " << line << "\n";
        if (!c.connected() && cmd != "quit" && cmd != "exit") { std::cout << "ERROR: connection lost\n"; exitCode = 1; break; }

        if (cmd == "quit" || cmd == "exit") break;
        else if (cmd == "help") help();
        else if (cmd == "register") {
            if (a.size() != 1) { std::cout << "usage: register <user>\n"; continue; }
            std::string p1 = readSecret("Password: "), p2 = readSecret("Repeat password: ");
            if (p1 != p2) { std::cout << "ERROR: passwords do not match\n"; continue; }
            show(c.registerUser(a[0], p1), "registered - you can now log in");
        } else if (cmd == "login") {
            if (a.size() != 1) { std::cout << "usage: login <user>\n"; continue; }
            Result r = c.login(a[0], readSecret("Password: "));
            if (r.ok) { g_cwd = "/"; std::cout << "Login successful! Role: " << roleName(c.role()) << "\n"; }
            else show(r);
        } else if (cmd == "logout") { show(c.logout()); g_cwd = "/"; }
        else if (cmd == "whoami") {
            if (c.loggedIn()) std::cout << c.username() << " (" << roleName(c.role()) << ")\n"; else std::cout << "not logged in\n";
        } else if (cmd == "pwd") std::cout << g_cwd << "\n";
        else if (cmd == "cd") {
            std::string p = resolve(a.empty() ? "/" : a[0]);
            std::vector<FileEntry> tmp;
            Result r = c.list(p, tmp);
            if (r.ok) g_cwd = p; else show(r);
        } else if (cmd == "ls") {
            bool longFmt = flag(a, "-l");
            std::vector<FileEntry> v;
            Result r = c.list(resolve(a.empty() ? "" : a[0]), v);
            if (!r.ok) show(r);
            else if (longFmt) printTable(v, false);
            else printListing(v);
        } else if (cmd == "search") {
            if (a.empty()) { std::cout << "usage: search <text>\n"; continue; }
            std::vector<FileEntry> v;
            Result r = c.search(a[0], v);
            if (r.ok) printTable(v, true); else show(r);
        } else if (cmd == "info") {
            if (a.size() != 1) { std::cout << "usage: info <path>\n"; continue; }
            FileEntry e;
            Result r = c.info(resolve(a[0]), e);
            if (!r.ok) { show(r); continue; }
            std::cout << "Path:        " << e.path << "\nType:        " << (e.isDir ? "directory" : "file") << "\n";
            if (!e.isDir) std::cout << "Size:        " << e.size << " bytes (" << humanSize(e.size) << ")\nSHA-256:     " << e.sha256
                                     << "\nShared:      " << (e.shared ? "yes" : "no") << "\n";
            std::cout << "Permissions: " << modeString(e.mode) << " (" << modeOctal(e.mode) << ")\n"
                      << "Owner:       " << e.owner << "\nCreated:     " << formatTime(e.created) << "\nModified:    " << formatTime(e.modified) << "\n";
        } else if (cmd == "upload") {
            bool sh = flag(a, "--shared"), ov = flag(a, "--overwrite");
            if (a.empty() || a.size() > 2) { std::cout << "usage: upload <local file> [remote dir] [--shared] [--overwrite]\n"; continue; }
            std::string local = a[0], base = local.substr(local.find_last_of('/') == std::string::npos ? 0 : local.find_last_of('/') + 1);
            uint64_t total = 0;
            int lastPct = -1;
            Result r = c.upload(local, resolve(a.size() > 1 ? a[1] : ""), base, sh, ov, [&](uint64_t d, uint64_t tot) {
                total = tot;
                int pct = tot ? int(d * 100 / tot) : 100;
                if (interactive && pct != lastPct) { lastPct = pct; std::cout << "\r  Uploading... " << pct << "%   " << std::flush; }
                return true;
            });
            if (interactive) std::cout << "\r";
            if (r.ok) std::cout << "Uploading... 100% (" << humanSize(total) << ")\nChecksum: VERIFIED (SHA-256, confirmed by server)\nUpload completed successfully.\n";
            else show(r);
        } else if (cmd == "download") {
            bool ov = flag(a, "--overwrite");
            if (a.empty() || a.size() > 2) { std::cout << "usage: download <remote file> [local path] [--overwrite]\n"; continue; }
            std::string remote = resolve(a[0]);
            std::string local = a.size() > 1 ? a[1] : remote.substr(remote.find_last_of('/') + 1);
            uint64_t total = 0;
            std::string sha;
            int lastPct = -1;
            Result r = c.download(remote, local, ov, [&](uint64_t d, uint64_t tot) {
                total = tot;
                int pct = tot ? int(d * 100 / tot) : 100;
                if (interactive && pct != lastPct) { lastPct = pct; std::cout << "\r  Downloading... " << pct << "%   " << std::flush; }
                return true;
            }, &sha);
            if (interactive) std::cout << "\r";
            if (r.ok) std::cout << "Downloading... 100% (" << humanSize(total) << ")\nChecksum: VERIFIED (SHA-256 " << sha.substr(0, 16)
                                 << "...)\nDownload completed successfully. Saved to " << local << "\n";
            else show(r);
        } else if (cmd == "rename") {
            if (a.size() != 2) { std::cout << "usage: rename <path> <new name>\n"; continue; }
            std::string np; Result r = c.rename(resolve(a[0]), a[1], &np);
            if (r.ok) std::cout << "renamed to " << np << "\n"; else show(r);
        } else if (cmd == "rm") { if (a.size() != 1) std::cout << "usage: delete <file>\n"; else show(c.removeFile(resolve(a[0]))); }
        else if (cmd == "mkdir") { if (a.size() != 1) std::cout << "usage: mkdir <path>\n"; else show(c.makeDir(resolve(a[0]))); }
        else if (cmd == "rmdir") { if (a.size() != 1) std::cout << "usage: rmdir <path>\n"; else show(c.removeDir(resolve(a[0]))); }
        else if (cmd == "share" || cmd == "unshare") { if (a.size() != 1) std::cout << "usage: share <file>\n"; else show(c.setShared(resolve(a[0]), cmd == "share")); }
        else if (cmd == "history") {
            std::vector<TransferEntry> v;
            Result r = c.history(a.empty() ? 20 : uint32_t(std::atoi(a[0].c_str())), v);
            if (!r.ok) { show(r); continue; }
            if (v.empty()) std::cout << "(no transfers yet)\n";
            for (auto& e : v)
                printf("#%-4lld %-19s %-8s %-9s %-10s %-10s %s\n", (long long)e.id, formatTime(e.started).c_str(), e.username.c_str(),
                       e.direction.c_str(), e.status.c_str(), humanSize(e.size).c_str(), e.path.c_str());
        } else if (cmd == "sysinfo") {
            KeyValues kv; Result r = c.sysinfo(kv);
            if (!r.ok) { show(r); continue; }
            for (auto& p : kv) printf("%-30s %s\n", p.first.c_str(), p.second.c_str());
        } else if (cmd == "users") {
            std::vector<UserEntry> v; Result r = c.listUsers(v);
            if (!r.ok) { show(r); continue; }
            printf("%-4s %-20s %-8s %-19s %s\n", "ID", "USERNAME", "ROLE", "CREATED", "LAST LOGIN");
            for (auto& u : v) printf("%-4lld %-20s %-8s %-19s %s\n", (long long)u.id, u.username.c_str(), u.role.c_str(), formatTime(u.created).c_str(), formatTime(u.lastLogin).c_str());
        } else if (cmd == "setrole") { if (a.size() != 2) std::cout << "usage: setrole <user> <role>\n"; else show(c.setUserRole(a[0], a[1])); }
        else if (cmd == "deluser") { if (a.size() != 1) std::cout << "usage: deluser <user>\n"; else show(c.deleteUser(a[0])); }
        else if (cmd == "audit") {
            std::vector<AuditEntry> v; Result r = c.audit(a.empty() ? 30 : uint32_t(std::atoi(a[0].c_str())), v);
            if (!r.ok) { show(r); continue; }
            for (auto& e : v) printf("%-19s %-10s %-14s %-8s %s %s\n", formatTime(e.ts).c_str(), e.username.c_str(), e.action.c_str(), e.result.c_str(), e.target.c_str(), e.detail.c_str());
        } else std::cout << "unknown command '" << t[0] << "' (try 'help')\n";
    }
    if (c.loggedIn()) c.logout();
    return exitCode;
}
