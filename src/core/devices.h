#pragma once
// Enumerating open targets other than files: running processes, raw disks / volumes, and the
// memory regions of a process. No UI. Windows: Toolhelp32 / VirtualQueryEx / \\.\PhysicalDriveN
// probing; Linux: /proc and /sys/block. Everything here is a quick, bounded OS query (fine on the
// UI thread when the user opens a picker or presses Refresh, not every frame).
#include <cstdint>
#include <string>
#include <vector>

namespace hx {

struct ProcessInfo {
    uint32_t pid = 0;
    std::string name;  // "notepad.exe" / "bash"
    std::string path;  // full executable path when it can be queried ("" otherwise)
    int bits = 0;      // 32 / 64; 0 = unknown (no access)
};
// All processes visible to us, sorted by name (case-insensitive), then pid.
std::vector<ProcessInfo> list_processes();
// Name of process `pid` ("" if there is no such process).
std::string process_name(uint32_t pid);

struct DeviceInfo {
    std::string path;         // "\\.\PhysicalDrive0", "\\.\C:", "/dev/sda", "/dev/nvme0n1p1"
    std::string description;  // model / volume label + file system
    uint64_t size = 0;        // bytes; 0 = unknown (no access)
    bool is_volume = false;   // a partition / logical volume (vs. a whole disk)
};
// Disks first (in OS order), then volumes / partitions. May be incomplete without admin / root.
std::vector<DeviceInfo> list_devices();

struct MemRegion {
    uint64_t base = 0;
    uint64_t size = 0;
    std::string prot;        // "rwx" with '-' for a missing right, e.g. "r-x"; "---" no access;
                             // Windows appends 'g' for guard pages, 'c' for copy-on-write
    bool readable = false;   // reads are expected to succeed (committed, accessible, no guard)
    bool writable = false;
    std::string type;        // Windows: "image" / "mapped" / "private"; Linux: "private" / "shared"
    std::string name;        // module / mapped file, "[heap]", "[stack]"... ("" anonymous)
    uint64_t end() const { return base + size; }
};
// Committed (Windows) / mapped (Linux) regions of `pid`, ascending, non-overlapping. `names`
// false skips the mapped-file names (Windows: one extra call per region). False + *err when the
// process cannot be queried (gone, access denied).
bool process_regions(uint32_t pid, std::vector<MemRegion>& out, std::string* err = nullptr, bool names = true);
// Size of the user address space a document of `pid` covers (one past the highest user address):
// 64-bit Windows 0x7FFFFFFF0000, WOW64 4 GiB, Linux x86-64 2^47 (or past its highest region).
uint64_t process_address_limit(uint32_t pid);
// Pointer width of `pid` (32 / 64; 0 unknown).
int process_bits(uint32_t pid);

}  // namespace hx
