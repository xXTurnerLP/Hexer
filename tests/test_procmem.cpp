// Tests for process memory / raw device targets: core/procmem (ByteBackend over a process address
// space), core/devices (process / device / region lists) and the Document target paths
// (open_process, open_device, fixed-size saves). The process under test is this test executable.
#include <doctest/doctest.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <memory>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include "core/devices.h"
#include "core/document.h"
#include "core/exe_map.h"
#include "core/file_source.h"
#include "core/nav.h"
#include "core/os_file.h"
#include "core/procmem.h"
#include "core/session.h"
#include "core/symbols.h"
#include "script/script_engine.h"
#include "symbol_fixture.h"

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#else
#include <dlfcn.h>
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

// ---- modules, in-memory PE symbols, follow-pointer width, Lua ---------------------------------------

namespace {

std::string lower_str(std::string s) {
    for (char& c : s) c = char(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

// The first symbol of that name / module (any case) and kind.
const Symbol* find_symbol(const SymbolTable& t, const std::string& name, const std::string& module,
                          Symbol::Kind kind) {
    for (const Symbol& s : t.symbols)
        if (s.name == name && s.kind == kind && lower_str(s.module) == lower_str(module)) return &s;
    return nullptr;
}

// symfix::make_pe() as the loader lays it out at `base` in memory (by RVA): headers at +0, .text
// (file 0x200) at +0x1000, .rdata (file 0x400) at +0x2000; the IAT holds resolved addresses.
// `oft` false clears the import descriptor's OriginalFirstThunk.
std::unique_ptr<Document> loaded_pe_doc(uint64_t base, bool oft = true) {
    const symfix::Bytes file = symfix::make_pe();
    symfix::Bytes mem(size_t(base + 0x3000), 0xCC);
    std::memcpy(mem.data() + base, file.data(), 0x200);
    std::memcpy(mem.data() + base + 0x1000, file.data() + 0x200, 0x200);
    std::memset(mem.data() + base + 0x1200, 0, 0xE00);
    std::memcpy(mem.data() + base + 0x2000, file.data() + 0x400, 0x400);
    std::memset(mem.data() + base + 0x2400, 0, 0xC00);
    symfix::put(mem, size_t(base + 0x2300), 0x7FF012345678ull, 8);  // resolved GetProcAddress
    symfix::put(mem, size_t(base + 0x2308), 0x7FF012340010ull, 8);  // resolved #16
    if (!oft) symfix::put(mem, size_t(base + 0x2200), 0, 4);
    return Document::create_from_bytes("image.bin", mem.data(), mem.size());
}

struct ProcHost : ScriptHost {
    std::vector<std::unique_ptr<Document>> docs;
    Document* active_document() override { return docs.empty() ? nullptr : docs.back().get(); }
    Document* find_document(uint64_t id) override {
        for (auto& d : docs)
            if (d->id() == id) return d.get();
        return nullptr;
    }
    Document* open_bytes(const std::string& name, const uint8_t* data, size_t len) override {
        docs.push_back(Document::create_from_bytes(name, data, len));
        return docs.back().get();
    }
    void reveal(Document&, uint64_t, uint64_t) override {}
    Document* open_process(uint32_t pid, bool writable, std::string* err) override {
        for (auto& d : docs)
            if (d->target() == SourceKind::Process && d->process_id() == pid && (!writable || !d->read_only()))
                return d.get();
        auto d = Document::open_process(pid, writable, err);
        if (!d) return nullptr;
        docs.push_back(std::move(d));
        return docs.back().get();
    }
};

}  // namespace

TEST_CASE("procmem: the module list holds this executable and the system libraries at their bases") {
    std::vector<ModuleInfo> mods;
    std::string err;
    REQUIRE_MESSAGE(process_modules(self_pid(), mods, &err), err);
    REQUIRE(mods.size() >= 2);
    for (size_t i = 1; i < mods.size(); ++i) CHECK(mods[i - 1].base < mods[i].base);  // ascending, each once
    for (const ModuleInfo& m : mods) {
        CHECK_FALSE(m.name.empty());
        CHECK(m.size > 0);
        CHECK(m.path.size() >= m.name.size());
    }
    const uint64_t code = addr_of(reinterpret_cast<const void*>(&self_pid));  // in this executable
    const ModuleInfo* exe = module_at(mods, code);
    REQUIRE(exe);
    CHECK(module_at(mods, exe->base) == exe);
    CHECK(module_at(mods, exe->end()) != exe);
    CHECK(module_at(mods, 0) == nullptr);
#ifdef _WIN32
    CHECK(exe->base == addr_of(GetModuleHandleW(nullptr)));
    wchar_t self[MAX_PATH];
    const DWORD n = GetModuleFileNameW(nullptr, self, MAX_PATH);
    CHECK(lower_str(exe->path) == lower_str(wide_to_utf8(std::wstring(self, n))));
    for (const wchar_t* dll : {L"kernel32.dll", L"ntdll.dll"}) {
        HMODULE h = GetModuleHandleW(dll);
        REQUIRE(h);
        const ModuleInfo* m = module_at(mods, addr_of(h));
        REQUIRE(m);
        CHECK(m->base == addr_of(h));
        CHECK(lower_str(m->name) == lower_str(wide_to_utf8(dll)));
        MODULEINFO mi{};
        REQUIRE(GetModuleInformation(GetCurrentProcess(), h, &mi, sizeof mi));
        CHECK(m->size == mi.SizeOfImage);
    }
#else
    Dl_info di{};
    REQUIRE(dladdr(reinterpret_cast<void*>(&self_pid), &di));
    CHECK(exe->base == addr_of(di.dli_fbase));
    char self[4096];
    const ssize_t n = readlink("/proc/self/exe", self, sizeof self);
    REQUIRE(n > 0);
    CHECK(exe->path == std::string(self, size_t(n)));
    void* fopen_fn = dlsym(RTLD_DEFAULT, "fopen");
    REQUIRE(fopen_fn);
    Dl_info li{};
    REQUIRE(dladdr(fopen_fn, &li));
    const ModuleInfo* libc = module_at(mods, addr_of(fopen_fn));
    REQUIRE(libc);
    CHECK(libc->base == addr_of(li.dli_fbase));
    CHECK(libc->name.find("libc") != std::string::npos);
#endif
    CHECK_FALSE(process_modules(0xFFFFFFF0u, mods, &err));  // no such process
    CHECK(mods.empty());
    CHECK_FALSE(err.empty());
}

TEST_CASE("procmem: a process document's address map names its modules and its pointer width") {
    std::string err;
    auto doc = Document::open_process(self_pid(), false, &err);
    REQUIRE_MESSAGE(doc, err);
    const AddressMap map = detect_address_map(*doc);
    CHECK(map.kind == AddressMap::Process);
    CHECK(map.bits == int(sizeof(void*) * 8));
    REQUIRE_FALSE(map.names.empty());
    const uint64_t code = addr_of(reinterpret_cast<const void*>(&self_pid));
    std::vector<ModuleInfo> mods;
    REQUIRE(process_modules(self_pid(), mods));
    const ModuleInfo* exe = module_at(mods, code);
    REQUIRE(exe);
    CHECK(map.section_at_va(code) == exe->name);
    CHECK(map.section_at_offset(code) == exe->name);
    uint64_t va = 0;
    CHECK(map.offset_to_va(code, va));  // still the identity
    CHECK(va == code);
#ifdef _WIN32
    // Go to Entry Point: the main module's (this test exe's) entry point, from its in-memory headers.
    REQUIRE(map.has_entry);
    CHECK(map.entry > exe->base);
    CHECK(map.entry < exe->base + exe->size);
    AddressMap img;
    REQUIRE(detect_pe_image(*doc->snapshot(), exe->base, img, &err));
    CHECK(map.entry == img.entry);
    uint64_t off = 0;
    CHECK(map.entry_offset(off));
    CHECK(off == map.entry);
#endif
}

TEST_CASE("procmem: detect_pe_image maps a loaded image by RVA and ignores the raw pointers") {
    const uint64_t base = 0x10000;
    auto doc = loaded_pe_doc(base);
    REQUIRE(doc);
    auto snap = doc->snapshot();
    AddressMap m;
    std::string err;
    REQUIRE_MESSAGE(detect_pe_image(*snap, base, m, &err), err);
    CHECK(m.kind == AddressMap::Pe);
    CHECK(m.in_memory);
    CHECK(m.base == base);  // the load address, not ImageBase 0x140000000
    CHECK(m.bits == 64);
    REQUIRE(m.regions.size() == 3);
    CHECK(m.regions[0].name == "(headers)");
    CHECK(m.regions[1].name == ".text");
    CHECK(m.regions[1].offset == base + 0x1000);   // by RVA, not PointerToRawData 0x200
    CHECK(m.regions[1].address == base + 0x1000);
    CHECK(m.regions[1].file_size == 0x1000);       // VirtualSize rounded to SectionAlignment
    CHECK(m.regions[1].exec);
    CHECK(m.regions[2].offset == base + 0x2000);
    CHECK(m.has_entry);
    CHECK(m.entry == base + 0x1000);
    uint64_t off = 0;
    CHECK(m.va_to_offset(base + 0x2100, off));
    CHECK(off == base + 0x2100);

    // Symbols through that map: addresses = load address + RVA, names from the in-memory tables.
    const SymbolTable t = build_symbols(*snap, m);
    const Symbol* alpha = find_symbol(t, "Alpha", "test.dll", Symbol::Export);
    REQUIRE(alpha);
    CHECK(alpha->address == base + 0x1000);
    REQUIRE(t.forwarders.size() == 1);
    CHECK(t.forwarders[0].forward == "NTDLL.RtlFoo");
    const Symbol* gpa = find_symbol(t, "GetProcAddress", "KERNEL32.dll", Symbol::Import);
    REQUIRE(gpa);
    CHECK(gpa->kind == Symbol::Import);
    CHECK(gpa->address == base + 0x2300);  // the IAT slot (it holds the resolved address)
    const Symbol* mb = find_symbol(t, "MessageBoxW", "USER32.dll", Symbol::Import);
    REQUIRE(mb);
    CHECK(mb->address == base + 0x2340);

    // A descriptor without OriginalFirstThunk: a loaded IAT has no names, nothing is invented.
    auto no_oft = loaded_pe_doc(base, false);
    REQUIRE(detect_pe_image(*no_oft->snapshot(), base, m, &err));
    const SymbolTable t2 = build_symbols(*no_oft->snapshot(), m);
    CHECK(find_symbol(t2, "GetProcAddress", "KERNEL32.dll", Symbol::Import) == nullptr);
    CHECK(find_symbol(t2, "Alpha", "test.dll", Symbol::Export) != nullptr);
    for (const Symbol& s : t2.symbols) CHECK(s.address != base + 0x2300);
}

TEST_CASE("procmem: detect_pe_image rejects what is not a loaded PE image") {
    const uint64_t base = 0x10000;
    AddressMap m;
    std::string err;
    {
        auto doc = loaded_pe_doc(base);
        CHECK_FALSE(detect_pe_image(*doc->snapshot(), base + 0x1000, m, &err));  // no MZ there
        CHECK(err.find("no PE image") != std::string::npos);
        CHECK_FALSE(detect_pe_image(*doc->snapshot(), UINT64_MAX - 8, m, &err));  // no overflow
    }
    auto patched = [&](size_t at, uint64_t v, int n) {
        const symfix::Bytes file = symfix::make_pe();
        symfix::Bytes mem(size_t(base + 0x3000), 0);
        std::memcpy(mem.data() + base, file.data(), 0x200);
        symfix::put(mem, size_t(base) + at, v, n);
        return Document::create_from_bytes("bad.bin", mem.data(), mem.size());
    };
    const size_t opt = 0x58, sec = opt + 0xF0;
    {
        auto doc = patched(opt + 56, 0x4000, 4);  // SizeOfImage past the end of the data
        CHECK_FALSE(detect_pe_image(*doc->snapshot(), base, m, &err));
        CHECK(err.find("SizeOfImage") != std::string::npos);
    }
    {
        auto doc = patched(sec + 12, 0x3000, 4);  // .text RVA == SizeOfImage
        CHECK_FALSE(detect_pe_image(*doc->snapshot(), base, m, &err));
        CHECK(err.find("outside SizeOfImage") != std::string::npos);
    }
    {
        auto doc = patched(sec + 40 + 12, 0x1100, 4);  // .rdata starts inside .text
        CHECK_FALSE(detect_pe_image(*doc->snapshot(), base, m, &err));
        CHECK(err.find("overlap") != std::string::npos);
    }
    {
        auto doc = patched(0x46, 2000, 2);  // absurd section count
        CHECK_FALSE(detect_pe_image(*doc->snapshot(), base, m, &err));
    }
    {
        auto doc = patched(0x40, 0, 4);  // no PE signature
        CHECK_FALSE(detect_pe_image(*doc->snapshot(), base, m, &err));
        CHECK(err.find("signature") != std::string::npos);
    }
}

#ifdef _WIN32
TEST_CASE("procmem: symbols of a process come from its modules' in-memory PE images") {
    std::string err;
    auto doc = Document::open_process(self_pid(), false, &err);
    REQUIRE_MESSAGE(doc, err);
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    REQUIRE(k32);
    auto snap = doc->snapshot();
    AddressMap img;
    REQUIRE_MESSAGE(detect_pe_image(*snap, addr_of(k32), img, &err), err);
    CHECK(img.in_memory);
    CHECK(img.format.find("image in memory") != std::string::npos);
    const uint64_t create_file = addr_of(reinterpret_cast<const void*>(GetProcAddress(k32, "CreateFileW")));
    CHECK(img.section_at_va(create_file) == ".text");

    const auto t0 = std::chrono::steady_clock::now();
    const SymbolTable t = build_symbols(*snap, detect_address_map(*doc));
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    MESSAGE(t.symbols.size() << " symbols of this process in " << ms << " ms");
    CHECK_FALSE(t.truncated);
    const Symbol* cf = find_symbol(t, "CreateFileW", "KERNEL32.dll", Symbol::Export);
    REQUIRE(cf);
    CHECK(cf->kind == Symbol::Export);
    CHECK(cf->label() == cf->module + "!CreateFileW");
    CHECK(cf->address == create_file);
    CHECK(t.at(cf->address) != nullptr);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    const Symbol* rtl = find_symbol(t, "RtlAllocateHeap", "ntdll.dll", Symbol::Export);
    REQUIRE(rtl);
    CHECK(rtl->address == addr_of(reinterpret_cast<const void*>(GetProcAddress(ntdll, "RtlAllocateHeap"))));

    // This executable's imports: one symbol per IAT slot, which holds the resolved function.
    std::vector<ModuleInfo> mods;
    REQUIRE(process_modules(self_pid(), mods));
    const ModuleInfo* exe = module_at(mods, addr_of(GetModuleHandleW(nullptr)));
    REQUIRE(exe);
    int checked = 0;
    for (const Symbol& s : t.symbols) {
        if (s.kind != Symbol::Import || s.address < exe->base || s.address >= exe->end()) continue;
        if (lower_str(s.module) != "kernel32.dll" || s.name.empty() || s.name[0] == '#') continue;
        uint64_t slot = 0;
        std::memcpy(&slot, reinterpret_cast<const void*>(uintptr_t(s.address)), sizeof slot);
        CHECK_MESSAGE(slot == addr_of(reinterpret_cast<const void*>(GetProcAddress(k32, s.name.c_str()))), s.name);
        ++checked;
    }
    CHECK(checked > 0);
    // Its entry point gets a name (it exports nothing).
    AddressMap exe_img;
    REQUIRE(detect_pe_image(*snap, exe->base, exe_img, &err));
    REQUIRE(exe_img.has_entry);
    const Symbol* entry = t.at(exe_img.entry);
    REQUIRE(entry);
    CHECK(entry->name == "entry");
    CHECK(entry->module == exe->name);
}

// A 32-bit (WOW64) process from this 64-bit one: its 32-bit modules are listed (each once), its
// map says 32-bit, and its PE32 images give symbols. Skipped where there is no SysWOW64.
TEST_CASE("procmem: a WOW64 process lists its 32-bit modules and gives PE32 symbols") {
    if (sizeof(void*) != 8) return;
    wchar_t sysdir[MAX_PATH];
    const UINT len = GetSystemWow64DirectoryW(sysdir, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) return;
    std::wstring cmd = L"\"" + std::wstring(sysdir, len) + L"\\PING.EXE\" -n 30 127.0.0.1";
    if (GetFileAttributesW((std::wstring(sysdir, len) + L"\\PING.EXE").c_str()) == INVALID_FILE_ATTRIBUTES) return;
    STARTUPINFOW si{};
    si.cb = sizeof si;
    PROCESS_INFORMATION pi{};
    REQUIRE(CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi));
    struct Kill {
        PROCESS_INFORMATION& p;
        ~Kill() {
            TerminateProcess(p.hProcess, 0);
            WaitForSingleObject(p.hProcess, 5000);
            CloseHandle(p.hThread);
            CloseHandle(p.hProcess);
        }
    } kill{pi};
    const uint32_t pid = pi.dwProcessId;
    CHECK(process_bits(pid) == 32);
    // Its loader runs on its own: wait until the 32-bit kernel32 is there.
    std::vector<ModuleInfo> mods;
    const ModuleInfo* k32 = nullptr;
    for (int i = 0; i < 100 && !k32; ++i) {
        process_modules(pid, mods);
        for (const ModuleInfo& m : mods)
            if (lower_str(m.name) == "kernel32.dll" && m.end() <= (1ull << 32)) k32 = &m;
        if (!k32) std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    REQUIRE(k32);
    for (size_t i = 1; i < mods.size(); ++i) CHECK(mods[i - 1].base < mods[i].base);  // each base once
    const auto exe_count = std::count_if(mods.begin(), mods.end(),
                                         [](const ModuleInfo& m) { return lower_str(m.name) == "ping.exe"; });
    CHECK(exe_count == 1);

    std::string err;
    auto doc = Document::open_process(pid, false, &err);
    REQUIRE_MESSAGE(doc, err);
    CHECK(doc->size() == (1ull << 32));
    const AddressMap map = detect_address_map(*doc);
    CHECK(map.bits == 32);
    AddressMap img;
    REQUIRE_MESSAGE(detect_pe_image(*doc->snapshot(), k32->base, img, &err), err);
    CHECK(img.bits == 32);
    CHECK(img.format.rfind("PE32 ", 0) == 0);
    const SymbolTable t = build_symbols(*doc->snapshot(), map);
    const Symbol* cf = find_symbol(t, "CreateFileW", "KERNEL32.dll", Symbol::Export);
    REQUIRE(cf);
    CHECK(cf->address > k32->base);
    CHECK(cf->address < k32->end());
    CHECK(map.section_at_va(cf->address) == k32->name);
}
#endif

TEST_CASE("procmem: process documents default the follow-pointer width until the user picks one") {
    AutoPointerWidth a;
    int width = 2;                   // the user's setting
    a.activate(8, width);            // a 64-bit process document becomes active
    CHECK(width == 8);
    CHECK(a.persisted(width) == 2);  // settings.ini keeps the user's width
    a.activate(4, width);            // a WOW64 one
    CHECK(width == 4);
    CHECK(a.persisted(width) == 2);
    a.activate(0, width);            // back to a file: the user's width again
    CHECK(width == 2);
    CHECK(a.persisted(width) == 2);
    a.activate(0, width);
    CHECK(width == 2);
    a.activate(8, width);
    CHECK(width == 8);
    width = 4;                       // the user picks 32-bit (Inspector row) while a process is active
    a.pick();
    CHECK(a.persisted(width) == 4);
    a.activate(0, width);            // the choice holds everywhere from now on
    CHECK(width == 4);
    a.activate(8, width);
    CHECK(width == 4);

    AutoPointerWidth b;              // picked before any process document was opened
    width = 2;
    b.pick();
    b.activate(8, width);
    CHECK(width == 2);
    AutoPointerWidth c;              // unknown pointer size: nothing changes
    width = 3;
    c.activate(0, width);
    CHECK(width == 3);
    CHECK(c.persisted(width) == 3);
}

TEST_CASE("procmem: Lua hx.open_process and doc:modules") {
    ProcHost host;
    ScriptEngine eng(&host);
    eng.set_script_dirs({});
    eng.reload();
    const uint64_t code = addr_of(reinterpret_cast<const void*>(&self_pid));
    std::string src = "local PID, CODE = " + std::to_string(self_pid()) + ", " + std::to_string(code) + "\n";
    src += R"(
        local d, err = hx.open_process(PID)
        assert(d, err)
        assert(d:target() == "process" and d:pid() == PID)
        local mods = assert(d:modules())
        assert(#mods > 0)
        local exe
        for i, m in ipairs(mods) do
            assert(type(m.name) == "string" and m.name ~= "" and type(m.path) == "string")
            assert(m.size > 0)
            if i > 1 then assert(mods[i - 1].base <= m.base) end
            if CODE >= m.base and CODE < m.base + m.size then exe = m end
        end
        assert(exe, "the test executable is not in the module list")
        assert(hx.open_process(PID):id() == d:id())             -- the open document is reused
        assert(hx.open_process(PID, { writable = false }):id() == d:id())
        local w = assert(hx.open_process(PID, { writable = true }))  -- the first one is read-only
        assert(w:id() ~= d:id())
        assert(hx.open_process(PID, { writable = true }):id() == w:id())
        local none, e2 = hx.open_process(4294967290)
        assert(none == nil and type(e2) == "string" and #e2 > 0, tostring(e2))
        assert(not pcall(hx.open_process, 0))
        assert(not pcall(hx.open_process, -1))
        assert(not pcall(hx.open_process, PID, 5))
        local f = hx.new_doc("plain.bin", "abc")
        assert(#f:modules() == 0)
    )";
#ifdef _WIN32
    src += R"(
        local found
        for _, s in ipairs(d:symbols()) do
            if s.name == "CreateFileW" and s.kind == "export" and s.module:lower() == "kernel32.dll" then found = s end
        end
        assert(found and found.kind == "export" and found.offset == found.address)
    )";
#endif
    std::string err;
    CHECK(eng.run_source(src, "open_process_test", &err));
    CHECK(err.empty());
    if (!err.empty()) MESSAGE(err);
    CHECK(host.docs.size() == 3);  // read-only + writable process documents + plain.bin
}

TEST_CASE("procmem: a process document starts at its main module, not in the hole at 0") {
    std::vector<ModuleInfo> mods;
    std::string err;
    REQUIRE_MESSAGE(process_modules(self_pid(), mods, &err), err);
    const ModuleInfo* exe = module_at(mods, addr_of(reinterpret_cast<const void*>(&self_pid)));
    REQUIRE(exe);
    CHECK(process_start_address(self_pid()) == exe->base);
    auto doc = Document::open_process(self_pid(), false, &err);
    REQUIRE_MESSAGE(doc, err);
    CHECK(doc->view().cursor == exe->base);
    CHECK_FALSE(doc->view().has_selection());
    uint8_t b = 0, bad = 1;
    REQUIRE(doc->read(doc->view().cursor, &b, 1, &bad) == 1);
    CHECK(bad == 0);  // the first byte shown is readable (the image header)
    CHECK_FALSE(doc->target_read_denied());  // this process's memory reads fine
    CHECK(process_start_address(0xFFFFFFF0u) == 0);  // no such process
}

TEST_CASE("procmem: readable_run_step merges adjacent readable regions and steps over holes") {
    auto reg = [](uint64_t base, uint64_t size, bool readable) {
        MemRegion r;
        r.base = base;
        r.size = size;
        r.readable = readable;
        return r;
    };
    // [0x1000,0x3000) readable (two regions), hole, [0x5000,0x6000) no access, [0x8000,0x9000),
    // [0x9000,0xA000) readable, hole, [0x20000,0x21000) at / above the limit.
    const std::vector<MemRegion> regs = {reg(0x1000, 0x1000, true), reg(0x2000, 0x1000, true),
                                         reg(0x5000, 0x1000, false), reg(0x8000, 0x1000, true),
                                         reg(0x9000, 0x1000, true), reg(0x20000, 0x1000, true)};
    const uint64_t limit = 0x20000;
    uint64_t b = 0, n = 0;
    auto fwd = [&](uint64_t from) { return readable_run_step(regs, limit, from, true, &b, &n); };
    auto back = [&](uint64_t from) { return readable_run_step(regs, limit, from, false, &b, &n); };

    REQUIRE(fwd(0));  // from the hole at 0
    CHECK(b == 0x1000);
    CHECK(n == 0x2000);  // merged
    REQUIRE(fwd(0x1000));  // from a run's start: the next run
    CHECK(b == 0x8000);
    CHECK(n == 0x2000);
    REQUIRE(fwd(0x2FFF));
    CHECK(b == 0x8000);
    REQUIRE(fwd(0x5800));  // inside the no-access region
    CHECK(b == 0x8000);
    CHECK_FALSE(fwd(0x8000));  // the last run below the limit
    CHECK_FALSE(fwd(0x1FFFF));

    CHECK_FALSE(back(0x2FFF));  // inside the first run: nothing before it
    REQUIRE(back(0x3000));      // just past it (in the hole)
    CHECK(b == 0x1000);
    REQUIRE(back(0x8000));  // a run's start: the run before
    CHECK(b == 0x1000);
    REQUIRE(back(0x9FFF));  // inside the second run (its second region): the run before
    CHECK(b == 0x1000);
    REQUIRE(back(0xFFFFFFFF));
    CHECK(b == 0x8000);
    CHECK(n == 0x2000);
    CHECK_FALSE(readable_run_step({}, limit, 0, true, &b, &n));
}

TEST_CASE("procmem: Next / Previous Readable Region step over a real hole of this process") {
    HoleyPages hp;  // readable | no access | readable
    const uint64_t a = addr_of(hp.base), pg = hp.pg;
    std::vector<MemRegion> regs;
    std::string err;
    REQUIRE_MESSAGE(process_regions(self_pid(), regs, &err, false), err);
    const uint64_t limit = process_address_limit(self_pid());
    uint64_t b = 0, n = 0;
    REQUIRE(readable_run_step(regs, limit, a, true, &b, &n));
    CHECK(b == a + 2 * pg);  // the page after the hole starts the next run
    REQUIRE(readable_run_step(regs, limit, a + 2 * pg, false, &b, &n));
    CHECK(b <= a);
    CHECK(b + n == a + pg);  // the run before ends at the hole
}

// A page that becomes unreadable after the region map was read (decommitted / unmapped) sits
// inside a region the map still calls readable, so the 64 KiB block read fails as a whole: the
// block then falls back to page-granular reads, and only that page shows "??" - the pages after
// it in the same block stay readable.
TEST_CASE("procmem: one failing page in a cached block does not blank the rest of the block") {
    const size_t pg = page_size();
#ifdef _WIN32
    auto* m = static_cast<uint8_t*>(VirtualAlloc(nullptr, 3 * pg, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    REQUIRE(m);
#else
    void* mm = mmap(nullptr, 3 * pg, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(mm != MAP_FAILED);
    auto* m = static_cast<uint8_t*>(mm);
#endif
    fill_pattern(m, 3 * pg, 21);
    std::string err;
    auto doc = Document::open_process(self_pid(), false, &err);  // its map: all three pages readable
    REQUIRE_MESSAGE(doc, err);
#ifdef _WIN32
    REQUIRE(VirtualFree(m + pg, pg, MEM_DECOMMIT));
#else
    REQUIRE(munmap(m + pg, pg) == 0);
#endif
    std::vector<uint8_t> buf(3 * pg), bad(3 * pg);
    CHECK(doc->read(addr_of(m), buf.data(), buf.size(), bad.data()) == buf.size());
    CHECK(std::count(bad.begin(), bad.begin() + std::ptrdiff_t(pg), uint8_t(1)) == 0);
    CHECK(std::count(bad.begin() + std::ptrdiff_t(pg), bad.begin() + std::ptrdiff_t(2 * pg), uint8_t(1)) ==
          std::ptrdiff_t(pg));
    CHECK(std::count(bad.begin() + std::ptrdiff_t(2 * pg), bad.end(), uint8_t(1)) == 0);
    CHECK(std::memcmp(buf.data(), m, pg) == 0);
    CHECK(std::memcmp(buf.data() + 2 * pg, m + 2 * pg, pg) == 0);
    CHECK_FALSE(doc->io_error());
#ifdef _WIN32
    VirtualFree(m, 0, MEM_RELEASE);
#else
    munmap(m, pg);
    munmap(m + 2 * pg, pg);
#endif
}
