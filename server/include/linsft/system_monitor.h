// Read-only Linux system monitoring via procfs/sysfs and POSIX calls. This is how LinSFT
// interacts with kernel drivers from user space (no kernel module is shipped).
#pragma once
#include <string>

#include "linsft/models.h"
#include "linsft/transfer_manager.h"

namespace linsft {

class SystemMonitor {
public:
    SystemMonitor(std::string storageRoot, ServerStats& stats, long startTime)
        : root_(std::move(storageRoot)), stats_(stats), start_(startTime) {}
    KeyValues snapshot(size_t activeSessions);
private:
    std::string root_;
    ServerStats& stats_;
    long start_;
};

}  // namespace linsft
