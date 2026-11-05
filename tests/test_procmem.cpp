// Tests for process memory / raw device targets: core/procmem (ByteBackend over a process address
// space), core/devices (process / device / region lists) and the Document target paths
// (open_process, open_device, fixed-size saves). The process under test is this test executable.
#include <doctest/doctest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include "core/devices.h"
#include "core/document.h"
#include "core/file_source.h"
#include "core/os_file.h"
#include "core/procmem.h"
#include "core/session.h"

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

using namespace hx;

namespace {

uint8_t g_target[8192];  // a known static buffer (read / written through the document)

uint32_t self_pid() { return uint32_t(os_process_id()); }
uint64_t addr_of(const void* p) { return uint64_t(reinterpret_cast<uintptr_t>(p)); }

void fill_pattern(uint8_t* p, size_t n, uint8_t seed) {
    for (size_t i = 0; i < n; ++i) p[i] = uint8_t(seed + i * 7);
}

size_t page_size() {
#ifdef _WIN32
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    return si.dwPageSize;
#else
    return size_t(sysconf(_SC_PAGESIZE));
#endif
}

// Three pages: readable | inaccessible (a hole) | readable. Released by the destructor.
struct HoleyPages {
    size_t pg = page_size();
    uint8_t* base = nullptr;
    HoleyPages() {
#ifdef _WIN32
        base = static_cast<uint8_t*>(VirtualAlloc(nullptr, 3 * pg, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        REQUIRE(base);
        fill_pattern(base, pg, 11);
        fill_pattern(base + 2 * pg, pg, 99);
        DWORD old = 0;
        REQUIRE(VirtualProtect(base + pg, pg, PAGE_NOACCESS, &old));
#else
        void* m = mmap(nullptr, 3 * pg, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        REQUIRE(m != MAP_FAILED);
        base = static_cast<uint8_t*>(m);
        fill_pattern(base, pg, 11);
        fill_pattern(base + 2 * pg, pg, 99);
        REQUIRE(mprotect(base + pg, pg, PROT_NONE) == 0);
#endif
    }
    ~HoleyPages() {
#ifdef _WIN32
        VirtualFree(base, 0, MEM_RELEASE);
#else
        munmap(base, 3 * pg);
#endif
    }
    HoleyPages(const HoleyPages&) = delete;
    HoleyPages& operator=(const HoleyPages&) = delete;
};

}  // namespace

TEST_CASE("procmem: process URL round trip") {
    uint32_t pid = 0;
    CHECK(parse_process_url(process_url(1234), &pid));
    CHECK(pid == 1234);
    CHECK_FALSE(parse_process_url("process://", &pid));
    CHECK_FALSE(parse_process_url("process://12a", &pid));
    CHECK_FALSE(parse_process_url("process://99999999999", &pid));
    CHECK_FALSE(parse_process_url("C:/x.bin", &pid));
    CHECK(os_absolute_path("process://1234") == "process://1234");  // not a file path
}

TEST_CASE("procmem: list_processes contains this process; list_devices does not crash") {
    const auto procs = list_processes();
    auto it = std::find_if(procs.begin(), procs.end(), [](const ProcessInfo& p) { return p.pid == self_pid(); });
    REQUIRE(it != procs.end());
    CHECK_FALSE(it->name.empty());
    CHECK(it->bits == int(sizeof(void*) * 8));
    CHECK(process_name(self_pid()) == it->name);
    CHECK(process_bits(self_pid()) == int(sizeof(void*) * 8));

    const auto devs = list_devices();  // may be empty without admin / root
    for (const DeviceInfo& d : devs) CHECK_FALSE(d.path.empty());
}

TEST_CASE("procmem: region list contains the static buffer's region") {
    std::vector<MemRegion> regs;
    std::string err;
    REQUIRE(process_regions(self_pid(), regs, &err));
    REQUIRE_FALSE(regs.empty());
    const uint64_t a = addr_of(g_target);
    auto it = std::find_if(regs.begin(), regs.end(), [&](const MemRegion& r) { return r.base <= a && a < r.end(); });
    REQUIRE(it != regs.end());
    CHECK(it->readable);
    CHECK(it->writable);
    CHECK(it->prot.substr(0, 2) == "rw");
    for (size_t i = 1; i < regs.size(); ++i) CHECK(regs[i - 1].end() <= regs[i].base);  // ascending, disjoint
    CHECK(regs.back().end() <= process_address_limit(self_pid()));
    CHECK_FALSE(process_regions(0xFFFFFFF0u, regs, &err));  // no such process
    CHECK_FALSE(err.empty());
}

TEST_CASE("procmem: read the own address space through a document") {
    fill_pattern(g_target, sizeof g_target, 3);
    std::string err;
    auto doc = Document::open_process(self_pid(), false, &err);
    REQUIRE_MESSAGE(doc, err);
    CHECK(doc->target() == SourceKind::Process);
    CHECK(doc->process_id() == self_pid());
    CHECK(doc->fixed_size());
    CHECK_FALSE(doc->persistable());
    CHECK(doc->read_only());
    CHECK(doc->target_alive());
    CHECK(doc->path() == process_url(self_pid()));
    CHECK(doc->display_name().find("(" + std::to_string(self_pid()) + ")") != std::string::npos);
    CHECK(doc->size() == process_address_limit(self_pid()));
    CHECK(doc->size() > addr_of(g_target));

    std::vector<uint8_t> buf(sizeof g_target);
    REQUIRE(doc->read(addr_of(g_target), buf.data(), buf.size()) == buf.size());
    CHECK(std::memcmp(buf.data(), g_target, buf.size()) == 0);

    // The null page is never mapped: unreadable bytes ("??"), not an I/O error.
    std::vector<uint8_t> bad(64, 0);
    doc->read(0, buf.data(), 64, bad.data());
    CHECK(std::count(bad.begin(), bad.end(), uint8_t(1)) == 64);
    CHECK_FALSE(doc->io_error());

    auto snap = doc->snapshot();
    CHECK(snap->read_valid(0, buf.data(), 64) == 0);
    const uint64_t r = snap->next_readable(0);
    CHECK(r > 0);
    CHECK(r <= addr_of(g_target));
    CHECK(snap->next_readable(addr_of(g_target)) == addr_of(g_target));
    CHECK(snap->next_readable(doc->size()) == doc->size());
    CHECK(snap->read_valid(addr_of(g_target), buf.data(), 256) == 256);

    // open_file accepts the URL too (read-only).
    auto again = Document::open_file(process_url(self_pid()), &err);
    REQUIRE(again);
    CHECK(again->target() == SourceKind::Process);
    CHECK(again->read_only());
}

TEST_CASE("procmem: holes inside the address space are skipped, not errors") {
    HoleyPages hp;
    const size_t pg = hp.pg;
    const uint64_t a = addr_of(hp.base);
    std::string err;
    auto doc = Document::open_process(self_pid(), false, &err);
    REQUIRE_MESSAGE(doc, err);

    std::vector<uint8_t> buf(3 * pg), bad(3 * pg);
    REQUIRE(doc->read(a, buf.data(), buf.size(), bad.data()) == buf.size());
    CHECK(std::memcmp(buf.data(), hp.base, pg) == 0);
    CHECK(std::memcmp(buf.data() + 2 * pg, hp.base + 2 * pg, pg) == 0);
    CHECK(std::count(bad.begin(), bad.begin() + pg, uint8_t(1)) == 0);
    CHECK(std::count(bad.begin() + pg, bad.begin() + 2 * pg, uint8_t(1)) == std::ptrdiff_t(pg));
    CHECK(std::count(bad.begin() + 2 * pg, bad.end(), uint8_t(1)) == 0);
    CHECK(std::all_of(buf.begin() + pg, buf.begin() + 2 * pg, [](uint8_t b) { return b == 0; }));
    CHECK_FALSE(doc->io_error());

    // How a background scan walks over it: read_valid stops at the hole, next_readable skips it.
    auto snap = doc->snapshot();
    uint64_t pos = a, readable = 0;
    const uint64_t end = a + 3 * pg;
    while (pos < end) {
        const size_t want = size_t(end - pos);
        const size_t got = snap->read_valid(pos, buf.data(), want);
        readable += got;
        if (got == want) break;
        const uint64_t next = snap->next_readable(pos + got);
        REQUIRE(next > pos + got);  // a hole, not an I/O error
        pos = next;
    }
    CHECK(readable == 2 * pg);
    CHECK(snap->next_readable(a + pg) == a + 2 * pg);
    CHECK(snap->next_readable(a + pg + 100) == a + 2 * pg);
}

TEST_CASE("procmem: write through the document and save into the process") {
    fill_pattern(g_target, sizeof g_target, 50);
    std::string err;
    auto doc = Document::open_process(self_pid(), true, &err);
    REQUIRE_MESSAGE(doc, err);
    CHECK_FALSE(doc->read_only());
    const uint64_t a = addr_of(g_target) + 100;
    const uint8_t hello[] = {'H', 'E', 'L', 'L', 'O'};
    REQUIRE(doc->overwrite(a, hello, sizeof hello));
    CHECK(doc->dirty());
    CHECK(g_target[100] != 'H');  // not written before the save
    REQUIRE_MESSAGE(doc->save(nullptr, &err), err);
    CHECK_FALSE(doc->dirty());
    const volatile uint8_t* t = g_target;
    CHECK(t[100] == 'H');
    CHECK(t[104] == 'O');
    CHECK(t[99] == uint8_t(50 + 99 * 7));  // neighbours untouched
    CHECK(t[105] == uint8_t(50 + 105 * 7));
    CHECK_FALSE(doc->last_save_info().backup_created);
    CHECK_FALSE(doc->changed_on_disk());

    // Undo restores the old bytes (history survives the in-place save) and saving writes them back.
    REQUIRE(doc->undo());
    REQUIRE_MESSAGE(doc->save(nullptr, &err), err);
    CHECK(t[100] == uint8_t(50 + 100 * 7));

    // The process changed its memory itself: refresh_target() shows it at once.
    std::vector<uint8_t> buf(4);
    g_target[200] = 0xAB;
    doc->refresh_target();
    REQUIRE(doc->read(addr_of(g_target) + 200, buf.data(), 1) == 1);
    CHECK(buf[0] == 0xAB);

    // Writing into a hole fails cleanly; the edit stays in the document.
    const uint8_t z = 1;
    REQUIRE(doc->overwrite(16, &z, 1));
    CHECK_FALSE(doc->save(nullptr, &err));
    CHECK_FALSE(err.empty());
    CHECK(doc->dirty());
}

TEST_CASE("procmem: fixed-size targets refuse size-changing saves; read-only by default") {
    fill_pattern(g_target, sizeof g_target, 9);
    std::string err;
    {
        auto doc = Document::open_process(self_pid(), false, &err);
        REQUIRE(doc);
        const uint8_t x = 'X';
        CHECK_FALSE(doc->overwrite(addr_of(g_target), &x, 1));  // read-only
        CHECK_FALSE(doc->save(nullptr, &err));
    }
    auto doc = Document::open_process(self_pid(), true, &err);
    REQUIRE_MESSAGE(doc, err);
    const uint64_t size = doc->size();
    const uint8_t ins[] = {1, 2, 3};
    REQUIRE(doc->insert(addr_of(g_target), ins, sizeof ins));  // accepted as an (undoable) edit
    CHECK(doc->size() == size + 3);
    CHECK_FALSE(doc->save(nullptr, &err));
    CHECK(err.find("Size-changing") != std::string::npos);
    CHECK(g_target[0] == 9);  // nothing written
    CHECK(doc->dirty());
    CHECK_FALSE(doc->save_as("unused.bin", nullptr, &err));  // a whole address space is no file
    REQUIRE(doc->undo());
    CHECK(doc->size() == size);
}

TEST_CASE("procmem: opening missing targets fails cleanly") {
    std::string err;
    CHECK_FALSE(Document::open_process(0xFFFFFFF0u, false, &err));
    CHECK_FALSE(err.empty());
    err.clear();
#ifdef _WIN32
    const std::string dev = "\\\\.\\PhysicalDrive987";
#else
    const std::string dev = "/dev/hexer-no-such-device";
#endif
    CHECK_FALSE(Document::open_device(dev, false, &err));
    CHECK_FALSE(err.empty());
    err.clear();
    CHECK_FALSE(Document::open_file(process_url(0xFFFFFFF0u), &err));
    CHECK_FALSE(err.empty());
}


namespace {

// Allocates / frees `pages` pages at a time until stopped; `last` is the latest base address.
struct Churn {
    std::atomic<bool> stop{false};
    std::atomic<uint64_t> last{0};
    std::atomic<uint64_t> rounds{0};
    std::thread th;
    explicit Churn(size_t pages) {
        th = std::thread([this, pages] {
            const size_t len = pages * page_size();
            while (!stop.load()) {
#ifdef _WIN32
                void* m = VirtualAlloc(nullptr, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (!m) continue;
#else
                void* m = mmap(nullptr, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
                if (m == MAP_FAILED) continue;
#endif
                std::memset(m, 0x5A, len);
                last = addr_of(m);
                std::this_thread::yield();
#ifdef _WIN32
                VirtualFree(m, 0, MEM_RELEASE);
#else
                munmap(m, len);
#endif
                rounds++;
            }
        });
    }
    ~Churn() {
        stop = true;
        th.join();
    }
};

double seconds_since(std::chrono::steady_clock::time_point t0) {
    return std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
}

}  // namespace

TEST_CASE("procmem: reading while regions come and go never fails hard") {
    std::string err;
    auto doc = Document::open_process(self_pid(), false, &err);
    REQUIRE_MESSAGE(doc, err);
    Churn churn(64);
    std::vector<uint8_t> buf(256 * 1024), bad(buf.size());
    const auto t0 = std::chrono::steady_clock::now();
    int iters = 0;
    while (seconds_since(t0) < 1.5) {
        const uint64_t at = churn.last.load();
        if (!at) continue;
        // Whatever the region does meanwhile: a full-length read (holes zero-filled), no I/O error.
        CHECK(doc->read(at - 4096, buf.data(), buf.size(), bad.data()) == buf.size());
        auto snap = doc->snapshot();
        const size_t got = snap->read_valid(at, buf.data(), buf.size());
        if (got < buf.size()) CHECK(snap->next_readable(at + got) > at + got);  // a hole, not an error
        CHECK(snap->next_readable(at) >= at);
        if (++iters % 50 == 0) doc->refresh_target();
    }
    CHECK(churn.rounds.load() > 0);
    CHECK(iters > 10);
    CHECK_FALSE(doc->io_error());
    CHECK(doc->target_alive());
}

TEST_CASE("procmem: an allocation made after opening becomes readable without a refresh") {
    std::string err;
    auto doc = Document::open_process(self_pid(), false, &err);
    REQUIRE_MESSAGE(doc, err);
    const size_t pg = page_size();
#ifdef _WIN32
    auto* m = static_cast<uint8_t*>(VirtualAlloc(nullptr, 4 * pg, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    REQUIRE(m);
#else
    void* raw = mmap(nullptr, 4 * pg, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(raw != MAP_FAILED);
    auto* m = static_cast<uint8_t*>(raw);
#endif
    fill_pattern(m, 4 * pg, 21);
    std::vector<uint8_t> buf(4 * pg);
    // The region map re-read runs in the background (at most once a second): the bytes appear
    // after a while, and reads never block on it meanwhile.
    const auto t0 = std::chrono::steady_clock::now();
    size_t got = 0;
    double slowest = 0;
    while (seconds_since(t0) < 5.0) {
        const auto r0 = std::chrono::steady_clock::now();
        got = doc->snapshot()->read_valid(addr_of(m), buf.data(), buf.size());
        slowest = std::max(slowest, seconds_since(r0));
        if (got == buf.size()) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    CHECK(got == buf.size());
    CHECK(std::memcmp(buf.data(), m, buf.size()) == 0);
    CHECK(slowest < 0.5);
#ifdef _WIN32
    VirtualFree(m, 0, MEM_RELEASE);
#else
    munmap(m, 4 * pg);
#endif
}

TEST_CASE("procmem: a whole address space walk skipping holes is quick") {
    std::string err;
    auto doc = Document::open_process(self_pid(), false, &err);
    REQUIRE_MESSAGE(doc, err);
    auto snap = doc->snapshot();
    std::vector<uint8_t> buf(1 << 20);
    const auto t0 = std::chrono::steady_clock::now();
    uint64_t pos = 0, readable = 0, holes = 0;
    bool saw_target = false;
    const uint64_t target = addr_of(g_target);
    while (pos < snap->size() && seconds_since(t0) < 30.0) {
        const size_t want = size_t(std::min<uint64_t>(buf.size(), snap->size() - pos));
        const size_t got = snap->read_valid(pos, buf.data(), want);
        readable += got;
        if (pos <= target && target < pos + got) saw_target = true;
        if (got == want) {
            pos += want;
            continue;
        }
        const uint64_t nx = snap->next_readable(pos + got);
        REQUIRE(nx > pos + got);  // holes only, no I/O error in the own process
        holes++;
        pos = nx;
    }
    CHECK(pos >= snap->size());
    CHECK(saw_target);
    CHECK(holes > 0);
    CHECK(readable > 0);
    CHECK_FALSE(doc->io_error());
    MESSAGE("walked " << readable << " readable bytes, " << holes << " holes in " << seconds_since(t0) << " s");
}

#ifdef _WIN32
TEST_CASE("procmem: a page that became a guard page after the map was read stays armed") {
    const size_t pg = page_size();
    auto* m = static_cast<uint8_t*>(VirtualAlloc(nullptr, 2 * pg, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    REQUIRE(m);
    fill_pattern(m, 2 * pg, 7);
    std::string err;
    auto doc = Document::open_process(self_pid(), true, &err);  // the map has both pages readable
    REQUIRE_MESSAGE(doc, err);
    DWORD old = 0;
    REQUIRE(VirtualProtect(m + pg, pg, PAGE_READWRITE | PAGE_GUARD, &old));
    std::vector<uint8_t> buf(2 * pg), bad(2 * pg);
    CHECK(doc->read(addr_of(m), buf.data(), buf.size(), bad.data()) == buf.size());
    CHECK(std::memcmp(buf.data(), m, pg) == 0);
    CHECK(std::count(bad.begin() + std::ptrdiff_t(pg), bad.end(), uint8_t(1)) == std::ptrdiff_t(pg));
    MEMORY_BASIC_INFORMATION mbi{};
    REQUIRE(VirtualQuery(m + pg, &mbi, sizeof mbi) == sizeof mbi);
    CHECK((mbi.Protect & PAGE_GUARD) != 0);  // still armed

    // Saving an overwrite of the guard page fails cleanly and leaves the guard armed.
    const uint8_t x = 0xEE;
    REQUIRE(doc->overwrite(addr_of(m) + pg, &x, 1));
    CHECK_FALSE(doc->save(nullptr, &err));
    REQUIRE(VirtualQuery(m + pg, &mbi, sizeof mbi) == sizeof mbi);
    CHECK((mbi.Protect & PAGE_GUARD) != 0);
    VirtualFree(m, 0, MEM_RELEASE);
}
#endif

TEST_CASE("procmem: the session never keeps a process document, even if handed one") {
    std::random_device rd;
    const std::filesystem::path dir =
        std::filesystem::temp_directory_path() / ("hexer-test-procmem-" + std::to_string(rd()) + std::to_string(rd()));
    std::filesystem::create_directories(dir);
    const std::string d = dir.string();
    std::string err;
    auto proc = Document::open_process(self_pid(), true, &err);
    REQUIRE_MESSAGE(proc, err);
    const uint8_t x = 1;
    REQUIRE(proc->overwrite(addr_of(g_target), &x, 1));  // dirty: still not kept
    auto file = Document::create_from_bytes("keep.bin", reinterpret_cast<const uint8_t*>("abc"), 3);
    REQUIRE(file);
    {
        Session s(d);
        REQUIRE_MESSAGE(s.save({proc.get(), file.get()}, 0, &err), err);
    }
    {
        Session s(d);
        Session::Restored r = s.load();
        REQUIRE(r.docs.size() == 1);
        CHECK(r.docs[0]->target() == SourceKind::File);
        CHECK(s.kept().empty());
    }
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

TEST_CASE("procmem: opening a listed disk either works read-only or fails with a rights hint") {
    const auto devs = list_devices();
    auto it = std::find_if(devs.begin(), devs.end(), [](const DeviceInfo& d) { return !d.is_volume; });
    if (it == devs.end()) return;  // no disks visible here
    std::string err;
    auto doc = Document::open_device(it->path, false, &err);
    if (!doc) {
        CHECK_FALSE(err.empty());
        if (err.find("denied") != std::string::npos) CHECK(err.find("administrator") != std::string::npos);
        MESSAGE("open_device(" << it->path << "): " << err);
        return;
    }
    CHECK(doc->target() == SourceKind::Device);
    CHECK(doc->read_only());
    CHECK(doc->fixed_size());
    CHECK(doc->persistable());
    CHECK(doc->size() > 0);
    uint8_t b[512];
    CHECK(doc->read(0, b, sizeof b) == sizeof b);
    CHECK_FALSE(doc->save(nullptr, &err));  // read-only
}

TEST_CASE("procmem: open_device refuses a regular file") {
    std::random_device rd;
    const std::filesystem::path f =
        std::filesystem::temp_directory_path() / ("hexer-test-procmem-" + std::to_string(rd()) + ".bin");
    REQUIRE(os_write_whole_atomic(f.string(), "abc", 3));
    std::string err;
    CHECK_FALSE(Document::open_device(f.string(), false, &err));
    CHECK(err.find("not a disk") != std::string::npos);
    std::error_code ec;
    std::filesystem::remove(f, ec);
}
