#pragma once
// Test helper: a sparse target with known holes - this test process's own memory, opened as a
// process document (core/procmem). HoleyMem allocates `before` readable pages, `hole` inaccessible
// pages (PAGE_NOACCESS / PROT_NONE: a hole of the region map, not an I/O error) and `after`
// readable pages, all zero-filled; released by the destructor.
#include <doctest/doctest.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

#include "core/document.h"
#include "core/os_file.h"

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

namespace hx_test {

inline uint64_t addr_of(const void* p) { return uint64_t(reinterpret_cast<uintptr_t>(p)); }

inline size_t page_size() {
#ifdef _WIN32
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    return si.dwPageSize;
#else
    return size_t(sysconf(_SC_PAGESIZE));
#endif
}

struct HoleyMem {
    size_t pg = page_size();
    size_t before, hole, after;
    uint8_t* base = nullptr;

    HoleyMem(size_t before_pages = 1, size_t hole_pages = 1, size_t after_pages = 1)
        : before(before_pages), hole(hole_pages), after(after_pages) {
        const size_t total = (before + hole + after) * pg;
#ifdef _WIN32
        base = static_cast<uint8_t*>(VirtualAlloc(nullptr, total, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        REQUIRE(base);
        DWORD old = 0;
        REQUIRE(VirtualProtect(base + before * pg, hole * pg, PAGE_NOACCESS, &old));
#else
        void* m = mmap(nullptr, total, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        REQUIRE(m != MAP_FAILED);
        base = static_cast<uint8_t*>(m);
        REQUIRE(mprotect(base + before * pg, hole * pg, PROT_NONE) == 0);
#endif
    }
    ~HoleyMem() {
#ifdef _WIN32
        VirtualFree(base, 0, MEM_RELEASE);
#else
        munmap(base, (before + hole + after) * pg);
#endif
    }
    HoleyMem(const HoleyMem&) = delete;
    HoleyMem& operator=(const HoleyMem&) = delete;

    uint64_t addr() const { return addr_of(base); }                     // first readable byte
    uint64_t hole_begin() const { return addr() + before * pg; }
    uint64_t hole_end() const { return addr() + (before + hole) * pg; }  // first byte after the hole
    uint64_t end() const { return addr() + (before + hole + after) * pg; }
    uint8_t* after_ptr() const { return base + (before + hole) * pg; }  // first page after the hole
};

// This process's address space as a document (read-only unless `writable`).
inline std::unique_ptr<hx::Document> open_self(bool writable = false) {
    std::string err;
    auto doc = hx::Document::open_process(uint32_t(hx::os_process_id()), writable, &err);
    REQUIRE_MESSAGE(doc, err);
    return doc;
}

}  // namespace hx_test
