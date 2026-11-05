#include "core/devices.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <iterator>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "core/os_file.h"

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <winioctl.h>
#else
#include <cerrno>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <fcntl.h>
#include <unistd.h>
#endif

namespace hx {

namespace {

std::string lower(std::string s) {
    for (char& c : s) c = char(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

std::string trim(std::string s) {
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.pop_back();
    size_t i = 0;
    while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i]))) ++i;
    return s.substr(i);
}

void sort_processes(std::vector<ProcessInfo>& v) {
    std::sort(v.begin(), v.end(), [](const ProcessInfo& a, const ProcessInfo& b) {
        const std::string la = lower(a.name), lb = lower(b.name);
        return la != lb ? la < lb : a.pid < b.pid;
    });
}

void set_err(std::string* err, const std::string& msg) {
    if (err) *err = msg;
}

}  // namespace

#ifdef _WIN32
// =============================================================================================
// Windows
// =============================================================================================
namespace {

std::string win_error(DWORD code) {
    wchar_t* buf = nullptr;
    DWORD n = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                                 FORMAT_MESSAGE_IGNORE_INSERTS,
                             nullptr, code, 0, reinterpret_cast<wchar_t*>(&buf), 0, nullptr);
    std::string msg;
    if (n && buf) msg = trim(wide_to_utf8(std::wstring(buf, n)));
    if (buf) LocalFree(buf);
    while (!msg.empty() && msg.back() == '.') msg.pop_back();
    return msg.empty() ? "error " + std::to_string(code) : msg;
}

struct Handle {
    HANDLE h = nullptr;
    explicit Handle(HANDLE x) : h(x == INVALID_HANDLE_VALUE ? nullptr : x) {}
    ~Handle() {
        if (h) CloseHandle(h);
    }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    explicit operator bool() const { return h != nullptr; }
};

bool self_is_wow64() {
    BOOL wow = FALSE;
    return IsWow64Process(GetCurrentProcess(), &wow) && wow;
}

int bits_of(HANDLE h) {
    BOOL wow = FALSE;
    if (!IsWow64Process(h, &wow)) return 0;
    if (wow) return 32;
    return (sizeof(void*) == 8 || self_is_wow64()) ? 64 : 32;
}

std::string image_path(HANDLE h) {
    std::wstring buf(32768, L'\0');
    DWORD n = DWORD(buf.size());
    if (!QueryFullProcessImageNameW(h, 0, buf.data(), &n)) return {};
    buf.resize(n);
    return wide_to_utf8(buf);
}

// "\Device\HarddiskVolume3\x.dll" -> "C:\x.dll" (GetMappedFileNameW returns NT device paths).
struct DosDevices {
    std::vector<std::pair<std::wstring, std::wstring>> map;  // NT prefix -> "C:"
    DosDevices() {
        wchar_t drives[512];
        DWORD n = GetLogicalDriveStringsW(DWORD(std::size(drives)), drives);
        if (n == 0 || n >= std::size(drives)) return;
        for (const wchar_t* d = drives; *d; d += wcslen(d) + 1) {
            std::wstring letter(d, 2);  // "C:"
            wchar_t target[1024];
            if (QueryDosDeviceW(letter.c_str(), target, DWORD(std::size(target)))) map.emplace_back(target, letter);
        }
    }
    std::string convert(const std::wstring& nt) const {
        for (const auto& [prefix, letter] : map)
            if (nt.size() > prefix.size() && nt.compare(0, prefix.size(), prefix) == 0 && nt[prefix.size()] == L'\\')
                return wide_to_utf8(letter + nt.substr(prefix.size()));
        return wide_to_utf8(nt);
    }
};

std::string prot_string(DWORD protect, bool* readable, bool* writable) {
    const DWORD base = protect & 0xFF;
    std::string s;
    bool r = false, w = false, cow = false;
    switch (base) {
    case PAGE_READONLY: s = "r--"; r = true; break;
    case PAGE_READWRITE: s = "rw-"; r = w = true; break;
    case PAGE_WRITECOPY: s = "rw-"; r = w = cow = true; break;
    case PAGE_EXECUTE: s = "--x"; break;
    case PAGE_EXECUTE_READ: s = "r-x"; r = true; break;
    case PAGE_EXECUTE_READWRITE: s = "rwx"; r = w = true; break;
    case PAGE_EXECUTE_WRITECOPY: s = "rwx"; r = w = cow = true; break;
    default: s = "---"; break;
    }
    const bool guard = (protect & PAGE_GUARD) != 0;
    if (guard) s += 'g';
    if (cow) s += 'c';
    *readable = r && !guard;
    *writable = w && !guard;
    return s;
}

uint64_t limit_for(HANDLE h) {
    if (bits_of(h) == 32) return 1ull << 32;
    SYSTEM_INFO si{};
    GetNativeSystemInfo(&si);
    const uint64_t max = uint64_t(reinterpret_cast<uintptr_t>(si.lpMaximumApplicationAddress));
    return (max + 0x10000) & ~uint64_t(0xFFFF);
}

}  // namespace

std::vector<ProcessInfo> list_processes() {
    std::vector<ProcessInfo> out;
    Handle snap(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!snap) return out;
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof pe;
    for (BOOL ok = Process32FirstW(snap.h, &pe); ok; ok = Process32NextW(snap.h, &pe)) {
        ProcessInfo p;
        p.pid = pe.th32ProcessID;
        p.name = wide_to_utf8(pe.szExeFile);
        Handle h(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, p.pid));
        if (h) {
            p.path = image_path(h.h);
            p.bits = bits_of(h.h);
        }
        out.push_back(std::move(p));
    }
    sort_processes(out);
    return out;
}

std::string process_name(uint32_t pid) {
    Handle h(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (h) {
        std::string p = image_path(h.h);
        if (!p.empty()) return path_filename(p);
    }
    Handle snap(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!snap) return {};
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof pe;
    for (BOOL ok = Process32FirstW(snap.h, &pe); ok; ok = Process32NextW(snap.h, &pe))
        if (pe.th32ProcessID == pid) return wide_to_utf8(pe.szExeFile);
    return {};
}

int process_bits(uint32_t pid) {
    Handle h(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    return h ? bits_of(h.h) : 0;
}

uint64_t process_address_limit(uint32_t pid) {
    Handle h(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (h) return limit_for(h.h);
    SYSTEM_INFO si{};
    GetNativeSystemInfo(&si);
    return (uint64_t(reinterpret_cast<uintptr_t>(si.lpMaximumApplicationAddress)) + 0x10000) & ~uint64_t(0xFFFF);
}

bool process_regions(uint32_t pid, std::vector<MemRegion>& out, std::string* err, bool names) {
    out.clear();
    HANDLE raw = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!raw) raw = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!raw) {
        set_err(err, "Cannot open process " + std::to_string(pid) + ": " + win_error(GetLastError()));
        return false;
    }
    Handle h(raw);
    const uint64_t limit = limit_for(h.h);
    std::unique_ptr<DosDevices> dos;
    uint64_t name_base = UINT64_MAX;  // AllocationBase whose name is in `name`
    std::string name;
    uint64_t addr = 0;
    MEMORY_BASIC_INFORMATION mbi{};
    while (addr < limit &&
           VirtualQueryEx(h.h, reinterpret_cast<LPCVOID>(uintptr_t(addr)), &mbi, sizeof mbi) == sizeof mbi) {
        const uint64_t base = uint64_t(reinterpret_cast<uintptr_t>(mbi.BaseAddress));
        const uint64_t size = uint64_t(mbi.RegionSize);
        if (size == 0 || base + size <= addr) break;
        if (mbi.State == MEM_COMMIT && base < limit) {
            MemRegion r;
            r.base = base;
            r.size = std::min<uint64_t>(size, limit - base);
            r.prot = prot_string(mbi.Protect, &r.readable, &r.writable);
            r.type = mbi.Type == MEM_IMAGE ? "image" : mbi.Type == MEM_MAPPED ? "mapped" : "private";
            if (names && mbi.Type != MEM_PRIVATE) {
                const uint64_t ab = uint64_t(reinterpret_cast<uintptr_t>(mbi.AllocationBase));
                if (ab != name_base) {
                    name_base = ab;
                    name.clear();
                    wchar_t buf[1024];
                    DWORD n = GetMappedFileNameW(h.h, mbi.BaseAddress, buf, DWORD(std::size(buf)));
                    if (n) {
                        if (!dos) dos = std::make_unique<DosDevices>();
                        name = dos->convert(std::wstring(buf, n));
                    }
                }
                r.name = name;
            }
            out.push_back(std::move(r));
        }
        addr = base + size;
    }
    return true;
}

std::vector<DeviceInfo> list_devices() {
    std::vector<DeviceInfo> out;
    const DWORD share = FILE_SHARE_READ | FILE_SHARE_WRITE;
    // Whole disks: access 0 is enough for the geometry / descriptor IOCTLs (no admin needed).
    for (int i = 0; i < 32; ++i) {
        DeviceInfo d;
        d.path = "\\\\.\\PhysicalDrive" + std::to_string(i);
        Handle h(CreateFileW(utf8_to_wide(d.path).c_str(), 0, share, nullptr, OPEN_EXISTING, 0, nullptr));
        if (!h) continue;
        alignas(8) uint8_t buf[1024];
        DWORD got = 0;
        if (DeviceIoControl(h.h, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, nullptr, 0, buf, sizeof buf, &got, nullptr) &&
            got >= sizeof(DISK_GEOMETRY) + sizeof(LARGE_INTEGER))
            d.size = uint64_t(reinterpret_cast<const DISK_GEOMETRY_EX*>(buf)->DiskSize.QuadPart);
        STORAGE_PROPERTY_QUERY q{};
        q.PropertyId = StorageDeviceProperty;
        q.QueryType = PropertyStandardQuery;
        std::memset(buf, 0, sizeof buf);
        if (DeviceIoControl(h.h, IOCTL_STORAGE_QUERY_PROPERTY, &q, sizeof q, buf, sizeof buf - 1, &got, nullptr) &&
            got >= sizeof(STORAGE_DEVICE_DESCRIPTOR)) {
            const auto* sd = reinterpret_cast<const STORAGE_DEVICE_DESCRIPTOR*>(buf);
            auto str = [&](DWORD off) {
                return off && off < got ? trim(reinterpret_cast<const char*>(buf + off)) : std::string();
            };
            std::string vendor = str(sd->VendorIdOffset), product = str(sd->ProductIdOffset);
            d.description = vendor.empty() ? product : product.empty() ? vendor : vendor + " " + product;
            if (sd->RemovableMedia) d.description += d.description.empty() ? "removable" : " (removable)";
        }
        out.push_back(std::move(d));
    }
    // Volumes with a drive letter.
    wchar_t drives[512];
    DWORD n = GetLogicalDriveStringsW(DWORD(std::size(drives)), drives);
    if (n && n < std::size(drives)) {
        for (const wchar_t* root = drives; *root; root += wcslen(root) + 1) {
            const UINT type = GetDriveTypeW(root);
            if (type == DRIVE_REMOTE || type == DRIVE_NO_ROOT_DIR || type == DRIVE_UNKNOWN) continue;
            DeviceInfo d;
            d.is_volume = true;
            d.path = "\\\\.\\" + wide_to_utf8(std::wstring(root, 2));
            Handle h(CreateFileW(utf8_to_wide(d.path).c_str(), 0, share, nullptr, OPEN_EXISTING, 0, nullptr));
            PARTITION_INFORMATION_EX pi{};
            DWORD got = 0;
            if (h && DeviceIoControl(h.h, IOCTL_DISK_GET_PARTITION_INFO_EX, nullptr, 0, &pi, sizeof pi, &got, nullptr))
                d.size = uint64_t(pi.PartitionLength.QuadPart);
            if (!d.size) {
                ULARGE_INTEGER total{};
                if (GetDiskFreeSpaceExW(root, nullptr, &total, nullptr)) d.size = total.QuadPart;
            }
            wchar_t label[MAX_PATH + 1] = {}, fs[MAX_PATH + 1] = {};
            const bool vi = GetVolumeInformationW(root, label, MAX_PATH, nullptr, nullptr, nullptr, fs, MAX_PATH);
            if (!vi && type == DRIVE_CDROM) continue;  // empty optical drive
            std::string desc = wide_to_utf8(label);
            if (fs[0]) desc += (desc.empty() ? "" : " ") + std::string("(") + wide_to_utf8(fs) + ")";
            if (type == DRIVE_REMOVABLE) desc += desc.empty() ? "removable" : ", removable";
            if (type == DRIVE_CDROM) desc += desc.empty() ? "optical" : ", optical";
            d.description = desc;
            out.push_back(std::move(d));
        }
    }
    return out;
}

#else
// =============================================================================================
// Linux / POSIX (/proc, /sys/block)
// =============================================================================================
namespace fs = std::filesystem;

namespace {

constexpr uint64_t kKernelHalf = 1ull << 63;  // regions at or above this are kernel addresses

std::string read_small(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

bool all_digits(const std::string& s) {
    if (s.empty()) return false;
    for (char c : s)
        if (c < '0' || c > '9') return false;
    return true;
}

std::string exe_path(uint32_t pid) {
    std::error_code ec;
    fs::path p = fs::read_symlink("/proc/" + std::to_string(pid) + "/exe", ec);
    return ec ? std::string() : p.string();
}

int elf_bits(uint32_t pid) {
    int fd = ::open(("/proc/" + std::to_string(pid) + "/exe").c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    unsigned char h[5] = {};
    ssize_t n = ::pread(fd, h, sizeof h, 0);
    ::close(fd);
    if (n != ssize_t(sizeof h) || std::memcmp(h, "\x7f" "ELF", 4) != 0) return 0;
    return h[4] == 1 ? 32 : h[4] == 2 ? 64 : 0;
}

std::string name_of(uint32_t pid, const std::string& path) {
    std::string comm = trim(read_small("/proc/" + std::to_string(pid) + "/comm"));
    // comm is truncated to 15 characters: prefer the executable name when it extends it.
    if (!path.empty()) {
        std::string base = path_filename(path);
        if (comm.empty() || (comm.size() >= 15 && base.rfind(comm, 0) == 0)) return base;
    }
    return comm;
}

uint64_t parse_hex(const char*& s) {
    uint64_t v = 0;
    for (;; ++s) {
        const char c = *s;
        int d = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
        if (d < 0) return v;
        v = v * 16 + uint64_t(d);
    }
}

uint64_t read_u64(const std::string& path) {
    std::string s = trim(read_small(path));
    return s.empty() ? 0 : std::strtoull(s.c_str(), nullptr, 10);
}

}  // namespace

std::vector<ProcessInfo> list_processes() {
    std::vector<ProcessInfo> out;
    std::error_code ec;
    for (fs::directory_iterator it("/proc", ec), end; !ec && it != end; it.increment(ec)) {
        const std::string fname = it->path().filename().string();
        if (!all_digits(fname)) continue;
        ProcessInfo p;
        p.pid = uint32_t(std::strtoul(fname.c_str(), nullptr, 10));
        p.path = exe_path(p.pid);
        p.name = name_of(p.pid, p.path);
        if (p.name.empty()) continue;  // exited meanwhile
        p.bits = p.path.empty() ? 0 : elf_bits(p.pid);
        out.push_back(std::move(p));
    }
    sort_processes(out);
    return out;
}

std::string process_name(uint32_t pid) { return name_of(pid, exe_path(pid)); }

int process_bits(uint32_t pid) {
    int b = elf_bits(pid);
    if (!b && pid == uint32_t(getpid())) b = int(sizeof(void*) * 8);
    return b;
}

bool process_regions(uint32_t pid, std::vector<MemRegion>& out, std::string* err, bool names) {
    out.clear();
    const std::string path = "/proc/" + std::to_string(pid) + "/maps";
    std::ifstream f(path);
    if (!f) {
        set_err(err, "Cannot read " + path + ": " + std::strerror(errno));
        return false;
    }
    std::string line;
    while (std::getline(f, line)) {
        // "7f1c2a000000-7f1c2a021000 rw-p 00000000 00:00 0      [heap]"
        const char* s = line.c_str();
        MemRegion r;
        r.base = parse_hex(s);
        if (*s != '-') continue;
        ++s;
        const uint64_t end = parse_hex(s);
        if (end <= r.base || r.base >= kKernelHalf) continue;  // [vsyscall] and friends
        r.size = end - r.base;
        while (*s == ' ') ++s;
        char perms[5] = {};
        for (int i = 0; i < 4 && *s && *s != ' '; ++i) perms[i] = *s++;
        r.prot.assign(perms, 3);
        r.readable = perms[0] == 'r';
        r.writable = perms[1] == 'w';
        r.type = perms[3] == 's' ? "shared" : "private";
        if (names) {
            // offset, dev, inode, then the optional path
            for (int field = 0; field < 3; ++field) {
                while (*s == ' ') ++s;
                while (*s && *s != ' ') ++s;
            }
            r.name = trim(s);
        }
        out.push_back(std::move(r));
    }
    std::sort(out.begin(), out.end(), [](const MemRegion& a, const MemRegion& b) { return a.base < b.base; });
    return true;
}

uint64_t process_address_limit(uint32_t pid) {
    uint64_t limit = process_bits(pid) == 32 ? (1ull << 32) : (1ull << 47);
    std::vector<MemRegion> regs;
    if (process_regions(pid, regs, nullptr, false) && !regs.empty())
        limit = std::max(limit, (regs.back().end() + 0xFFF) & ~uint64_t(0xFFF));
    return limit;
}

std::vector<DeviceInfo> list_devices() {
    std::vector<DeviceInfo> disks, parts;
    std::error_code ec;
    std::vector<std::string> names;
    for (fs::directory_iterator it("/sys/block", ec), end; !ec && it != end; it.increment(ec))
        names.push_back(it->path().filename().string());
    std::sort(names.begin(), names.end());
    for (const std::string& name : names) {
        const std::string sys = "/sys/block/" + name;
        DeviceInfo d;
        d.path = "/dev/" + name;
        d.size = read_u64(sys + "/size") * 512;
        if (d.size == 0) continue;  // empty loop device, no media
        if (name.rfind("loop", 0) == 0) {
            d.description = "loop: " + trim(read_small(sys + "/loop/backing_file"));
        } else if (name.rfind("dm-", 0) == 0) {
            d.description = "device mapper: " + trim(read_small(sys + "/dm/name"));
            d.is_volume = true;
        } else {
            std::string vendor = trim(read_small(sys + "/device/vendor")), model = trim(read_small(sys + "/device/model"));
            d.description = vendor.empty() ? model : model.empty() ? vendor : vendor + " " + model;
            if (trim(read_small(sys + "/removable")) == "1") d.description += d.description.empty() ? "removable" : " (removable)";
        }
        (d.is_volume ? parts : disks).push_back(d);
        std::vector<std::string> sub;
        for (fs::directory_iterator it(sys, ec), end; !ec && it != end; it.increment(ec)) {
            std::error_code ec2;
            if (fs::exists(it->path() / "partition", ec2)) sub.push_back(it->path().filename().string());
        }
        std::sort(sub.begin(), sub.end());
        ec.clear();
        for (const std::string& p : sub) {
            DeviceInfo v;
            v.path = "/dev/" + p;
            v.size = read_u64(sys + "/" + p + "/size") * 512;
            v.is_volume = true;
            v.description = "partition " + trim(read_small(sys + "/" + p + "/partition")) + " of " + name;
            parts.push_back(std::move(v));
        }
    }
    disks.insert(disks.end(), parts.begin(), parts.end());
    return disks;
}

#endif

}  // namespace hx
