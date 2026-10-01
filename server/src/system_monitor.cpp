#include "linsft/system_monitor.h"

#include <dirent.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <map>
#include <sstream>
#include <vector>

namespace linsft {

static std::string readFirstLine(const std::string& path) {
    std::ifstream f(path);
    std::string line;
    if (f) std::getline(f, line);
    return line;
}

static std::string kbToHuman(unsigned long long kb) { return humanSize(kb * 1024ULL); }

KeyValues SystemMonitor::snapshot(size_t activeSessions) {
    KeyValues kv;
    auto add = [&](const std::string& k, const std::string& v) { kv.emplace_back(k, v); };

    // --- server runtime stats (from this process) ---
    long up = long(time(nullptr)) - start_;
    add("Server uptime", std::to_string(up / 3600) + "h " + std::to_string((up / 60) % 60) + "m " + std::to_string(up % 60) + "s");
    add("Active connections", std::to_string(stats_.connectionsActive.load()));
    add("Total connections", std::to_string(stats_.connectionsTotal.load()));
    add("Active sessions", std::to_string(activeSessions));
    add("Requests handled", std::to_string(stats_.requests.load()));
    add("Protocol errors", std::to_string(stats_.protocolErrors.load()));
    add("Uploads completed", std::to_string(stats_.uploadsCompleted.load()));
    add("Downloads completed", std::to_string(stats_.downloadsCompleted.load()));
    add("Bytes received", humanSize(stats_.bytesReceived.load()));
    add("Bytes sent", humanSize(stats_.bytesSent.load()));
    add("Server PID", std::to_string(getpid()));

    // --- /proc/self/status: threads + resident memory ---
    {
        std::ifstream f("/proc/self/status");
        std::string line;
        while (std::getline(f, line)) {
            if (line.rfind("Threads:", 0) == 0) add("Server threads", std::to_string(std::atoi(line.c_str() + 8)));
            if (line.rfind("VmRSS:", 0) == 0) {
                unsigned long long kb = std::strtoull(line.c_str() + 6, nullptr, 10);
                add("Server resident memory", kbToHuman(kb));
            }
        }
    }

    // --- /proc/loadavg, /proc/uptime, /proc/meminfo ---
    std::string la = readFirstLine("/proc/loadavg");
    if (!la.empty()) {
        std::istringstream ss(la);
        std::string a, b, c;
        ss >> a >> b >> c;
        add("Load average (1/5/15 min)", a + " " + b + " " + c);
    }
    std::string ut = readFirstLine("/proc/uptime");
    if (!ut.empty()) {
        long s = long(std::strtod(ut.c_str(), nullptr));
        add("Host uptime", std::to_string(s / 86400) + "d " + std::to_string((s / 3600) % 24) + "h " + std::to_string((s / 60) % 60) + "m");
    }
    {
        std::ifstream f("/proc/meminfo");
        std::string key, unit;
        unsigned long long val;
        std::map<std::string, unsigned long long> m;
        while (f >> key >> val >> unit) m[key] = val;  // "MemTotal: 123 kB"
        if (m.count("MemTotal:")) add("Memory total", kbToHuman(m["MemTotal:"]));
        if (m.count("MemAvailable:")) add("Memory available", kbToHuman(m["MemAvailable:"]));
    }
    add("CPU cores online", std::to_string(sysconf(_SC_NPROCESSORS_ONLN)));

    // --- storage filesystem via statvfs(2) ---
    struct statvfs sv;
    if (::statvfs(root_.c_str(), &sv) == 0) {
        unsigned long long total = (unsigned long long)sv.f_blocks * sv.f_frsize;
        unsigned long long avail = (unsigned long long)sv.f_bavail * sv.f_frsize;
        add("Storage filesystem total", humanSize(total));
        add("Storage filesystem free", humanSize(avail));
    }

    // --- device driver interfaces: character device node + major->driver map ---
    std::map<int, std::string> charDrivers, blockDrivers;
    {
        std::ifstream f("/proc/devices");
        std::string line;
        bool block = false;
        while (std::getline(f, line)) {
            if (line.rfind("Character devices:", 0) == 0) { block = false; continue; }
            if (line.rfind("Block devices:", 0) == 0) { block = true; continue; }
            int major; char name[64];
            if (std::sscanf(line.c_str(), "%d %63s", &major, name) == 2)
                (block ? blockDrivers : charDrivers)[major] = name;
        }
    }
    struct stat st;
    if (::stat("/dev/urandom", &st) == 0 && S_ISCHR(st.st_mode)) {
        int mj = int(major(st.st_rdev)), mn = int(minor(st.st_rdev));
        std::string drv = charDrivers.count(mj) ? charDrivers[mj] : "unknown";
        add("Entropy device /dev/urandom",
            "char device " + std::to_string(mj) + ":" + std::to_string(mn) + ", kernel driver '" + drv + "' (used for salts/tokens)");
    }
    // block devices from sysfs
    DIR* d = ::opendir("/sys/block");
    if (d) {
        std::vector<std::string> names;
        while (struct dirent* de = ::readdir(d))
            if (de->d_name[0] != '.') names.push_back(de->d_name);
        ::closedir(d);
        std::sort(names.begin(), names.end());
        int shown = 0;
        for (auto& n : names) {
            if (n.rfind("loop", 0) == 0 || n.rfind("ram", 0) == 0) continue;  // skip virtual noise
            std::string sectors = readFirstLine("/sys/block/" + n + "/size");
            unsigned long long sz = std::strtoull(sectors.c_str(), nullptr, 10) * 512ULL;
            std::string rot = readFirstLine("/sys/block/" + n + "/queue/rotational");
            std::string devMM = readFirstLine("/sys/block/" + n + "/dev");
            std::string desc = humanSize(sz) + ", dev " + devMM + (rot == "0" ? ", non-rotational" : rot == "1" ? ", rotational" : "");
            int mj = std::atoi(devMM.c_str());
            if (blockDrivers.count(mj)) desc += ", driver '" + blockDrivers[mj] + "'";
            add("Block device " + n, desc);
            if (++shown >= 8) break;
        }
        add("Block devices listed", std::to_string(shown) + " (from /sys/block, loop/ram excluded)");
    }
    return kv;
}

}  // namespace linsft
