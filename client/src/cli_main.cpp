// network-file-client: interactive / scriptable command line client for LinSFT.
#include <termios.h>
#include <unistd.h>

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

static std::string readSecret(const std::string& prompt) {
    bool tty = isatty(STDIN_FILENO);
    termios oldt{};
    if (tty) { tcgetattr(STDIN_FILENO, &oldt); termios nt = oldt; nt.c_lflag &= ~tcflag_t(ECHO); tcsetattr(STDIN_FILENO, TCSANOW, &nt); }
    std::cout << prompt << std::flush;
    std::string s;
    std::getline(std::cin, s);
    if (tty) { tcsetattr(STDIN_FILENO, TCSANOW, &oldt); std::cout << "\n"; }
    return s;
}

static void show(const Result& r, const char* okMsg = nullptr) {
    if (r.ok) std::cout << (okMsg ? okMsg : r.message.c_str()) << "\n";
    else std::cout << "ERROR [" << statusName(r.status) << "]: " << r.message << "\n";
}

static void printEntries(const std::vector<FileEntry>& v, bool withPath) {
    if (v.empty()) { std::cout << "(empty)\n"; return; }
    printf("%-4s %-10s %-10s %-7s %-19s %s\n", "TYPE", "SIZE", "OWNER", "SHARED", "MODIFIED", "NAME");
    for (auto& e : v)
        printf("%-4s %-10s %-10s %-7s %-19s %s\n", e.isDir ? "dir" : "file", e.isDir ? "-" : humanSize(e.size).c_str(),
               e.owner.c_str(), e.isDir ? "-" : (e.shared ? "yes" : "no"), formatTime(e.modified).c_str(),
               (withPath ? e.path : e.name + (e.isDir ? "/" : "")).c_str());
}

static void help() {
    std::puts(
        "Commands:\n"
        "  register <user>            create a STUDENT account\n"
        "  login <user>               sign in (password prompt)\n"
        "  logout | whoami\n"
        "  ls [path]  cd <path>  pwd  search <text>  info <path>\n"
        "  upload <local file> [remote dir] [--shared] [--overwrite]\n"
        "  download <remote file> [local path] [--overwrite]\n"
        "  rename <path> <new name>   rm <file>   mkdir <path>   rmdir <path>\n"
        "  share <file>  unshare <file>\n"
        "  history [n]\n"
        "  sysinfo                    (FACULTY/ADMIN)\n"
        "  users | setrole <user> <STUDENT|FACULTY|ADMIN> | deluser <user> | audit [n]   (ADMIN)\n"
        "  help  quit");
}

static bool flag(std::vector<std::string>& a, const std::string& f) {
    for (size_t i = 0; i < a.size(); ++i) if (a[i] == f) { a.erase(a.begin() + long(i)); return true; }
    return false;
}

int main(int argc, char** argv) {
    std::string host = "127.0.0.1";
    uint16_t port = 9090;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if ((a == "--host" || a == "-H") && i + 1 < argc) host = argv[++i];
        else if ((a == "--port" || a == "-p") && i + 1 < argc) port = uint16_t(std::atoi(argv[++i]));
        else if (a == "--help" || a == "-h") {
            std::puts("Usage: network-file-client [--host HOST] [--port PORT]\nReads commands from the terminal (or stdin). Type 'help' inside.");
            return 0;
        } else { std::cerr << "unknown option " << a << "\n"; return 2; }
    }
    Client c;
    Result cr = c.connectTo(host, port);
    if (!cr.ok) { std::cerr << "ERROR: " << cr.message << "\n(Is network-file-server running?)\n"; return 1; }
    bool interactive = isatty(STDIN_FILENO);
    std::cout << "Connected to " << host << ":" << port << ". Type 'help' for commands.\n";
    std::string line;
    int exitCode = 0;
    for (;;) {
        if (interactive) {
            std::cout << (c.loggedIn() ? c.username() + "@linsft" : "linsft") << ":" << g_cwd << "> " << std::flush;
        }
        if (!std::getline(std::cin, line)) break;
        auto t = tokenize(line);
        if (t.empty() || t[0][0] == '#') continue;
        std::string cmd = t[0];
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
            if (r.ok) { g_cwd = "/"; std::cout << "Logged in as " << c.username() << " (" << roleName(c.role()) << ")\n"; }
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
            std::vector<FileEntry> v;
            Result r = c.list(resolve(a.empty() ? "" : a[0]), v);
            if (r.ok) printEntries(v, false); else show(r);
        } else if (cmd == "search") {
            if (a.empty()) { std::cout << "usage: search <text>\n"; continue; }
            std::vector<FileEntry> v;
            Result r = c.search(a[0], v);
            if (r.ok) printEntries(v, true); else show(r);
        } else if (cmd == "info") {
            if (a.size() != 1) { std::cout << "usage: info <path>\n"; continue; }
            FileEntry e;
            Result r = c.info(resolve(a[0]), e);
            if (!r.ok) { show(r); continue; }
            std::cout << "Path:     " << e.path << "\nType:     " << (e.isDir ? "directory" : "file") << "\n";
            if (!e.isDir) std::cout << "Size:     " << e.size << " bytes (" << humanSize(e.size) << ")\nSHA-256:  " << e.sha256
                                     << "\nShared:   " << (e.shared ? "yes" : "no") << "\n";
            std::cout << "Owner:    " << e.owner << "\nCreated:  " << formatTime(e.created) << "\nModified: " << formatTime(e.modified) << "\n";
        } else if (cmd == "upload") {
            bool sh = flag(a, "--shared"), ov = flag(a, "--overwrite");
            if (a.empty() || a.size() > 2) { std::cout << "usage: upload <local file> [remote dir] [--shared] [--overwrite]\n"; continue; }
            std::string local = a[0], base = local.substr(local.find_last_of('/') == std::string::npos ? 0 : local.find_last_of('/') + 1);
            Result r = c.upload(local, resolve(a.size() > 1 ? a[1] : ""), base, sh, ov, [&](uint64_t d, uint64_t tot) {
                if (interactive && tot > 0) { std::cout << "\r  uploading " << humanSize(d) << " / " << humanSize(tot) << "   " << std::flush; }
                return true;
            });
            if (interactive) std::cout << "\r";
            show(r, "upload complete, SHA-256 verified by server");
        } else if (cmd == "download") {
            bool ov = flag(a, "--overwrite");
            if (a.empty() || a.size() > 2) { std::cout << "usage: download <remote file> [local path] [--overwrite]\n"; continue; }
            std::string remote = resolve(a[0]);
            std::string local = a.size() > 1 ? a[1] : remote.substr(remote.find_last_of('/') + 1);
            Result r = c.download(remote, local, ov, [&](uint64_t d, uint64_t tot) {
                if (interactive && tot > 0) { std::cout << "\r  downloading " << humanSize(d) << " / " << humanSize(tot) << "   " << std::flush; }
                return true;
            });
            if (interactive) std::cout << "\r";
            if (r.ok) std::cout << "saved to " << local << " - " << r.message << "\n"; else show(r);
        } else if (cmd == "rename") {
            if (a.size() != 2) { std::cout << "usage: rename <path> <new name>\n"; continue; }
            std::string np; Result r = c.rename(resolve(a[0]), a[1], &np);
            if (r.ok) std::cout << "renamed to " << np << "\n"; else show(r);
        } else if (cmd == "rm") { if (a.size() != 1) std::cout << "usage: rm <file>\n"; else show(c.removeFile(resolve(a[0]))); }
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
        } else std::cout << "unknown command '" << cmd << "' (try 'help')\n";
    }
    if (c.loggedIn()) c.logout();
    return exitCode;
}
