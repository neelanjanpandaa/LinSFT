// Read-only Linux system monitoring via procfs/sysfs and POSIX calls, plus the optional
// "securemon" kernel module (driver/securemon.c) read through its character device.
#pragma once
#include <string>

#include "linsft/models.h"
#include "linsft/transfer_manager.h"

namespace linsft {

// Result of reading the securemon character device (key=value text produced by the kernel module).
struct DriverReading {
    bool available = false;
    std::string error;   // strerror text when the device could not be opened/read
    KeyValues values;
};
DriverReading readSecuremon(const std::string& devicePath);

class SystemMonitor {
public:
    SystemMonitor(std::string storageRoot, ServerStats& stats, long startTime)
        : root_(std::move(storageRoot)), stats_(stats), start_(startTime) {}
    void setDriverPath(std::string p) { driverPath_ = std::move(p); }
    KeyValues snapshot(size_t activeSessions);
private:
    std::string root_;
    ServerStats& stats_;
    long start_;
    std::string driverPath_ = "/dev/securemon";
};

}  // namespace linsft
