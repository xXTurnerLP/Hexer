#ifndef _WIN32
#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif
#endif

#include "core/procmem.h"

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <mutex>
#include <thread>
#include <vector>

#include "core/devices.h"
#include "core/os_file.h"

#ifdef _WIN32
#include <windows.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace hx {

namespace {

using Clock = std::chrono::steady_clock;
constexpr auto kMissRefresh = std::chrono::seconds(1);  // re-read the map on a miss at most this often

struct Span {
    uint64_t base, end;  // readable [base, end)
};
using Map = std::vector<Span>;

#ifdef _WIN32
constexpr uint64_t kPage = 4096;

std::string win_error(DWORD code) {
    wchar_t* buf = nullptr;
    DWORD n = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                                 FORMAT_MESSAGE_IGNORE_INSERTS,
                             nullptr, code, 0, reinterpret_cast<wchar_t*>(&buf), 0, nullptr);
    std::string msg;
    if (n && buf) msg = wide_to_utf8(std::wstring(buf, n));
    if (buf) LocalFree(buf);
    while (!msg.empty() && (msg.back() == '\n' || msg.back() == '\r' || msg.back() == ' ' || msg.back() == '.'))
        msg.pop_back();
    return msg.empty() ? "error " + std::to_string(code) : msg;
}
#endif

class ProcessBackend final : public ByteBackend {
public:
    ~ProcessBackend() override {
        {
            std::lock_guard<std::mutex> lk(mu_);
            stop_ = true;
        }
        cv_.notify_all();
        if (worker_.joinable()) worker_.join();
#ifdef _WIN32
        if (h_) CloseHandle(h_);
#else
        if (fd_ >= 0) ::close(fd_);
#endif
    }

    bool open(uint32_t pid, bool write, std::string* err) {
        pid_ = pid;
        write_ = write;
        const std::string who = "process " + std::to_string(pid);
#ifdef _WIN32
        DWORD access = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | SYNCHRONIZE;
        if (write) access |= PROCESS_VM_WRITE | PROCESS_VM_OPERATION;
        h_ = OpenProcess(access, FALSE, pid);
        if (!h_) {
            const DWORD e = GetLastError();
            std::string msg = e == ERROR_INVALID_PARAMETER ? "no such process" : win_error(e);
            if (e == ERROR_ACCESS_DENIED) msg += " (try running Hexer as administrator)";
            if (err) *err = "Cannot open " + who + ": " + msg;
            return false;
        }
#else
        const std::string mem = "/proc/" + std::to_string(pid) + "/mem";
        do {
            fd_ = ::open(mem.c_str(), (write ? O_RDWR : O_RDONLY) | O_CLOEXEC);
        } while (fd_ < 0 && errno == EINTR);
        if (fd_ < 0) {
            const int e = errno;
            std::string msg = e == ENOENT ? "no such process" : std::strerror(e);
            if (e == EACCES || e == EPERM)
                msg += " (needs ptrace access: run as the same user with kernel.yama.ptrace_scope allowing it, or as root)";
            if (err) *err = "Cannot open " + who + ": " + msg;
            return false;
        }
#endif
        size_ = process_address_limit(pid);
        std::string e;
        if (!reload(&e)) {
            if (err) *err = "Cannot read the memory map of " + who + ": " + e;
            return false;
        }
        denied_ = probe_denied();
        return true;
    }

    uint64_t size() const override { return size_; }
    bool sparse() const override { return true; }
    bool writable() const override { return write_; }

    size_t read(uint64_t off, uint8_t* dst, size_t n) const override {
        size_t done = 0;
        std::shared_ptr<const Map> m = map(off);
        while (done < n) {
            const uint64_t pos = off + done;
            const Span* s = span_at(*m, pos);
            if (!s) break;  // hole
            const size_t chunk = size_t(std::min<uint64_t>(n - done, s->end - pos));
            const size_t got = os_read(pos, dst + done, chunk);
            done += got;
            if (got < chunk) break;
        }
        return done;
    }

    uint64_t next_readable(uint64_t off) const override {
        if (off >= size_) return size_;
        std::shared_ptr<const Map> m = map(off);
        auto it = std::upper_bound(m->begin(), m->end(), off, [](uint64_t v, const Span& s) { return v < s.end; });
        if (it == m->end()) return size_;
        return std::max(off, it->base);
    }

    bool write(uint64_t off, const uint8_t* src, size_t n) override {
        if (!write_) return false;
        if (n == 0) return true;
#ifdef _WIN32
        SIZE_T w = 0;
        return WriteProcessMemory(h_, reinterpret_cast<LPVOID>(uintptr_t(off)), src, n, &w) && w == n;
#else
        size_t done = 0;
        while (done < n) {
            ssize_t r = ::pwrite(fd_, src + done, n - done, off_t(off + done));
            if (r < 0 && errno == EINTR) continue;
            if (r <= 0) return false;
            done += size_t(r);
        }
        return true;
#endif
    }

    void refresh() override { reload(nullptr); }

    bool read_denied() const override { return denied_; }

    bool alive() const override {
#ifdef _WIN32
        return WaitForSingleObject(h_, 0) == WAIT_TIMEOUT;
#else
        return ::kill(pid_t(pid_), 0) == 0 || errno == EPERM;
#endif
    }

private:
    // Readable regions (merged, clipped to size_). False if the process cannot be queried.
    bool reload(std::string* err) const {
        std::vector<MemRegion> regs;
        auto m = std::make_shared<Map>();
        const bool ok = process_regions(pid_, regs, err, false);
        for (const MemRegion& r : regs) {
            if (!r.readable || r.base >= size_) continue;
            const uint64_t end = std::min(r.end(), size_);
            if (!m->empty() && m->back().end == r.base) m->back().end = end;
            else m->push_back({r.base, end});
        }
        std::lock_guard<std::mutex> lk(mu_);
        map_ = std::move(m);  // empty when the process cannot be queried (gone): all holes
        map_time_ = Clock::now();
        return ok;
    }

    static const Span* span_at(const Map& m, uint64_t pos) {
        auto it = std::upper_bound(m.begin(), m.end(), pos, [](uint64_t v, const Span& s) { return v < s.end; });
        return it != m.end() && it->base <= pos ? &*it : nullptr;
    }

    // The current map; when `pos` is outside every region and the map is older than a second, a
    // re-read is requested (a new allocation may live there now). It runs on a worker thread:
    // listing a large process (10k+ regions) takes tens of ms, and this is called from the UI
    // thread's reads. The new map is used as soon as it is there.
    std::shared_ptr<const Map> map(uint64_t pos) const {
        std::shared_ptr<const Map> m;
        {
            std::lock_guard<std::mutex> lk(mu_);
            m = map_;
        }
        if (!span_at(*m, pos)) request_reload();
        return m;
    }

    // Asks the worker to re-read the map, at most once per kMissRefresh.
    void request_reload() const {
        std::lock_guard<std::mutex> lk(mu_);
        if (stop_ || want_reload_ || Clock::now() - map_time_ < kMissRefresh) return;
        want_reload_ = true;
        map_time_ = Clock::now();  // no further requests until this one is done + kMissRefresh
        if (!worker_.joinable()) worker_ = std::thread([this] { reload_loop(); });
        cv_.notify_one();
    }

    void reload_loop() const {
        std::unique_lock<std::mutex> lk(mu_);
        for (;;) {
            cv_.wait(lk, [this] { return stop_ || want_reload_; });
            if (stop_) return;
            want_reload_ = false;
            lk.unlock();
            reload(nullptr);
            lk.lock();
        }
    }

    // True when not one of the first readable regions gives a byte: the memory exists (the map
    // lists it) but reads are refused, e.g. a protected process or ptrace rules.
    bool probe_denied() const {
        std::shared_ptr<const Map> m;
        {
            std::lock_guard<std::mutex> lk(mu_);
            m = map_;
        }
        size_t tried = 0;
        for (const Span& s : *m) {
            uint8_t b = 0;
            if (os_read(s.base, &b, 1) == 1) return false;
            if (++tried == 16) break;
        }
        return tried > 0;
    }

    // Reads a range inside one readable region; on a failure, page by page up to the first bad page.
    size_t os_read(uint64_t pos, uint8_t* dst, size_t n) const {
#ifdef _WIN32
        SIZE_T got = 0;
        if (ReadProcessMemory(h_, reinterpret_cast<LPCVOID>(uintptr_t(pos)), dst, n, &got) && got == n) return n;
        size_t done = 0;
        while (done < n) {
            const size_t c = size_t(std::min<uint64_t>(n - done, kPage - (pos + done) % kPage));
            got = 0;
            if (!ReadProcessMemory(h_, reinterpret_cast<LPCVOID>(uintptr_t(pos + done)), dst + done, c, &got) || got != c)
                break;
            done += c;
        }
        return done;
#else
        size_t done = 0;
        while (done < n) {
            ssize_t r = ::pread(fd_, dst + done, n - done, off_t(pos + done));
            if (r < 0 && errno == EINTR) continue;
            if (r <= 0) break;
            done += size_t(r);
        }
        return done;
#endif
    }

    uint32_t pid_ = 0;
    bool write_ = false;
    bool denied_ = false;  // probe_denied() at open
    uint64_t size_ = 0;
#ifdef _WIN32
    HANDLE h_ = nullptr;
#else
    int fd_ = -1;
#endif
    mutable std::mutex mu_;                   // guards map_ / map_time_ / want_reload_ / stop_ / worker_
    mutable std::shared_ptr<const Map> map_;
    mutable Clock::time_point map_time_{};
    mutable std::condition_variable cv_;      // wakes the map re-read worker
    mutable std::thread worker_;              // started by the first request_reload()
    mutable bool want_reload_ = false;
    bool stop_ = false;
};

}  // namespace

std::unique_ptr<ByteBackend> open_process_backend(uint32_t pid, bool write, std::string* err) {
    auto be = std::make_unique<ProcessBackend>();
    if (!be->open(pid, write, err)) return nullptr;
    return be;
}

bool parse_process_url(const std::string& path, uint32_t* pid) {
    static const char kPrefix[] = "process://";
    const size_t k = sizeof kPrefix - 1;
    if (path.size() <= k || path.compare(0, k, kPrefix) != 0 || path.size() - k > 10) return false;
    uint64_t v = 0;
    for (size_t i = k; i < path.size(); ++i) {
        if (path[i] < '0' || path[i] > '9') return false;
        v = v * 10 + uint64_t(path[i] - '0');
    }
    if (v > UINT32_MAX) return false;
    if (pid) *pid = uint32_t(v);
    return true;
}

std::string process_url(uint32_t pid) { return "process://" + std::to_string(pid); }

uint64_t process_start_address(uint32_t pid) {
    const uint64_t limit = process_address_limit(pid);
    std::string name = process_name(pid);
    std::vector<ModuleInfo> mods;
    if (!name.empty() && process_modules(pid, mods)) {
        auto lower = [](std::string v) {
            for (char& c : v)
                if (c >= 'A' && c <= 'Z') c = char(c - 'A' + 'a');
            return v;
        };
        name = lower(name);
        for (const ModuleInfo& m : mods)
            if (m.base < limit && lower(m.name) == name) return m.base;
    }
    std::vector<MemRegion> regs;
    process_regions(pid, regs, nullptr, false);
    for (const MemRegion& r : regs)
        if (r.readable && r.base < limit) return r.base;
    return 0;
}

bool readable_run_step(const std::vector<MemRegion>& regs, uint64_t limit, uint64_t from, bool forward,
                       uint64_t* base, uint64_t* size) {
    bool found = false;
    uint64_t rb = 0, re = 0;      // the run being merged
    uint64_t best_b = 0, best_e = 0;
    auto consider = [&](uint64_t b, uint64_t e) {
        // Forward: the first run starting after `from`; backward: the last one ending at or before it.
        if (forward ? (!found && b > from) : e <= from) {
            found = true;
            best_b = b;
            best_e = e;
        }
    };
    bool open = false;
    for (const MemRegion& r : regs) {
        if (!r.readable || r.size == 0 || r.base >= limit) continue;
        const uint64_t e = std::min(r.end(), limit);
        if (open && r.base == re) {
            re = e;
            continue;
        }
        if (open) consider(rb, re);
        rb = r.base;
        re = e;
        open = true;
    }
    if (open) consider(rb, re);
    if (!found) return false;
    if (base) *base = best_b;
    if (size) *size = best_e - best_b;
    return true;
}

}  // namespace hx
