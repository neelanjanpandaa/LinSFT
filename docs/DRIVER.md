# securemon kernel module

| Item | Value (from the source) |
|---|---|
| Source / Makefile | `driver/securemon.c`, `driver/Makefile` (kbuild, uses headers of the running kernel) |
| Module / file | `securemon` / `securemon.ko` |
| Device | `/dev/securemon`, dynamic major (`alloc_chrdev_region`), minor 0, mode 0444, created via class + `device_create` |
| Operations | `open`, `read`, `release` only. No `write`, no `ioctl`, no procfs/sysfs |
| Output | key=value lines: `securemon_version, uptime_s, online_cpus, mem_total_kb, mem_free_kb, kernel_release, page_size, hz, device_opens, device_reads` |
| Data sources | `ktime_get_boottime_seconds()`, `num_online_cpus()`, `si_meminfo()`, `init_utsname()`, `PAGE_SIZE`, `HZ`, module counters |
| LinSFT use | `SystemMonitor` reads the device on each `SYSINFO` (FACULTY/ADMIN). Missing device -> "securemon driver = not loaded (...)" |

## Build / load / unload
```bash
sudo apt install -y build-essential kmod linux-headers-$(uname -r)
make -C driver
modinfo driver/securemon.ko        # vermagic must equal `uname -r`
sudo insmod driver/securemon.ko    # or: sudo rmmod securemon
lsmod | grep securemon; ls -l /dev/securemon; cat /dev/securemon; sudo dmesg | tail
```

## Full runtime verification (real Linux VM only)
```bash
cmake -S . -B build && cmake --build build -j$(nproc)
sudo scripts/vm_verify_driver.sh     # writes evidence/driver/*.txt and summary.tsv
```
Covers: headers, build, vermagic, device absent before load, insmod, device node, read, comparison with
`uname -r` / `nproc` / `getconf PAGESIZE` / `/proc/meminfo`, rejected write, 50x open/close, real server + CLI `SYSINFO`,
dmesg activity, rmmod, node removal, 3 repeat cycles, dmesg error scan.

## Status rules
PASS only with real runtime evidence in `evidence/driver/`. WSL2 and containers cannot load modules: record BLOCKED, with the exact
error. Secure Boot rejects unsigned modules ("Key was rejected by service"): record BLOCKED, do not bypass silently.
The unit tests `securemon_reader_*` use a plain file as a stand-in and verify only the user-space parser (EMULATED).
