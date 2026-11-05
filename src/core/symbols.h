#pragma once
// Symbol names of an executable image for the Disassembly panel (labels, branch / call / IAT
// annotations, Go to Symbol) and doc:symbols.
//
//   * PE (needs a detected PE AddressMap): the export directory (names + ordinals -> RVA; an
//     export without a name is "#<ordinal>"; a forwarded export - RVA inside the export directory -
//     goes to `forwarders` with its "DLL.Function" text, it has no address), the import directory
//     and the delay-load import directory (one Import symbol per IAT slot: "DLL!Function" or
//     "DLL!#<ordinal>", PE32 4-byte and PE32+ 8-byte thunks; the names come from the
//     OriginalFirstThunk / name table, else from the IAT itself).
//   * ELF: .symtab and .dynsym STT_FUNC / STT_GNU_IFUNC (Function) and STT_OBJECT (Object) symbols
//     with a value != 0 in a real section (not UNDEF / ABS / COMMON). ET_EXEC / ET_DYN (needs a
//     detected ELF map): st_value is the address; ET_REL (any map but Process): section offset +
//     st_value through AddressMap::offset_to_va. Imports: JUMP_SLOT / GLOB_DAT relocations
//     (x86-64 and i386) give "name@got" at the GOT slot; every "jmp [rip+X]" / "jmp [X]" (with an
//     optional endbr / bnd prefix) in .plt / .plt.sec / .plt.got that reads such a slot gives
//     "name@plt" at that PLT entry. i386 PIC PLTs (jmp [ebx+X]) get no @plt names.
//   * PE / ELF entry point without a symbol of its own: Function "entry" (stripped images).
//   * Process memory (a Process map, whose `names` are the loaded modules): the exports / imports
//     of every module's PE image as mapped in memory (detect_pe_image: headers at the load
//     address, tables by RVA, addresses = load address + RVA; import descriptors without an
//     OriginalFirstThunk are skipped - a loaded IAT holds addresses, not names), plus
//     "<module>!entry" at each entry point. A Pe map with in_memory set works the same for one
//     image. Linux (ELF modules): none yet.
//   * Anything else (None / Manual maps for PE / ELF executables): empty.
//
// Bounded and checked: every read is range-checked against the snapshot, counts are capped
// (kMaxSymbols in total, kMaxName bytes per name, kMaxNameBytes of names, kMaxModules import
// descriptors), a malformed table only loses its own entries, and the build stops after
// SymbolLimits::max_ms (truncated = true). Reads go through a Snapshot so a build can run on a
// worker thread (SymbolJob) while the UI keeps the previous table.
#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "core/document.h"
#include "core/exe_map.h"

namespace hx {

struct Symbol {
    enum Kind : uint8_t { Export, Function, Object, Import };  // also the order at one address

    uint64_t address = 0;   // virtual address (Import: the IAT / GOT slot, or the PLT entry)
    std::string name;       // "CreateFileW", "#12" (ordinal only), "puts@plt", "puts@got"
    std::string module;     // PE: export / import DLL name ("KERNEL32.dll"); ELF: ""
    std::string forward;    // forwarded PE export: "NTDLL.RtlAllocateHeap" (then no address)
    uint32_t ordinal = 0;   // PE export ordinal / import by ordinal (0 = none)
    Kind kind = Function;

    // "KERNEL32.dll!CreateFileW", or the plain name when there is no module.
    std::string label() const { return module.empty() ? name : module + "!" + name; }
};

const char* symbol_kind_name(Symbol::Kind k);  // "export" | "function" | "object" | "import"

struct SymbolLimits {
    size_t max_symbols = 1000000;
    int max_ms = 3000;      // wall-clock budget of one build (0 = none)
};

struct SymbolTable {
    static constexpr size_t kMaxName = 4096;               // longer names are cut
    static constexpr uint64_t kMaxNameBytes = 64ull << 20; // all names together
    static constexpr size_t kMaxModules = 4096;            // import descriptors per directory

    std::vector<Symbol> symbols;     // sorted by (address, kind, name); duplicates removed
    std::vector<Symbol> forwarders;  // forwarded exports (no address), in export order
    bool truncated = false;          // a cap or the time budget cut the build short
    std::string note;                // what was skipped / why ("export directory: ...")
    // File ranges [begin, end) the build read (headers, directories, tables, names, PLT bytes):
    // sorted, merged, small gaps between them included. The table depends on nothing else but
    // these bytes, the map, the limits and the document size (SymbolJob skips rebuilds with it).
    std::vector<std::pair<uint64_t, uint64_t>> sources;

    bool empty() const { return symbols.empty() && forwarders.empty(); }
    // The first symbol at exactly `va` (exports before functions, objects, imports), or nullptr.
    const Symbol* at(uint64_t va) const;
    // The closest non-import symbol at or before `va` (*delta = va - its address), or nullptr.
    const Symbol* nearest(uint64_t va, uint64_t* delta = nullptr) const;
    // Sorts / dedupes `symbols` and builds the lookup index (build_symbols calls it).
    void finalize();
    // Go to Symbol filtering: the indices of the symbols whose label() contains `filter` (ASCII
    // case ignored), in table order; every index for "". One pass over a lowercase copy of all
    // labels made by index_labels() (SymbolJob calls it on its worker; without it, slower).
    void match(std::string_view filter, std::vector<uint32_t>& out) const;
    void index_labels();

private:
    std::vector<uint32_t> code_;     // indices of the non-import symbols (address order)
    std::string lower_;              // index_labels(): every label lowercased, each ending in a newline
    std::vector<size_t> lower_at_;   // start of symbol i's label in lower_ (+ the end)
};

// Builds the symbols of `snap` (the document's bytes) under `map` (detect_address_map of the same
// document). `cancel` (may be null) stops it early. Never fails: unknown formats give an empty table.
SymbolTable build_symbols(const Snapshot& snap, const AddressMap& map, const SymbolLimits& lim = {},
                          const std::atomic<bool>* cancel = nullptr);

// True when `a` and `b` have the same size and every byte of `ranges` comes from the same place in
// both (the same file version / add-buffer chunk at the same position, compared piece by piece:
// O(pieces in the ranges), no bytes are read). An overwrite inside a range (even with equal
// bytes) or an insert / delete before its end makes it false; undo back to `a`'s pieces true.
bool same_bytes(const Snapshot& a, const Snapshot& b, const std::vector<std::pair<uint64_t, uint64_t>>& ranges);

// Background builds on one worker thread of its own (started by the first build). start() never
// blocks: it hands the request to the worker and cancels the build running there (that one stops
// within one table entry and is dropped); a request not yet picked up is replaced by a newer one.
// result() is the last finished table (null before the first one finishes) and stays until the
// next build finishes, so the UI never shows an empty table while rebuilding after an edit.
// The worker also calls index_labels() on every table.
class SymbolJob {
public:
    SymbolJob() = default;
    ~SymbolJob();  // cancels a running build and joins the worker
    SymbolJob(const SymbolJob&) = delete;
    SymbolJob& operator=(const SymbolJob&) = delete;

    // Builds the table of `snap` under `map`, unless nothing it depends on changed: when no build
    // is pending and the last result was built under an equal map and limits, from a snapshot
    // with same_bytes(that snapshot, *snap, result()->sources), the result is kept for `snap`
    // (returns false; current() stays true). So an edit outside the tables' bytes (patching code)
    // costs no rebuild; a size change always rebuilds. Process memory (a Process map, a Pe map
    // in_memory) always rebuilds: its bytes change without edits. So does a truncated table (the
    // time budget may have cut it) and a file version rewritten since (in-place save).
    bool start(std::shared_ptr<const Snapshot> snap, AddressMap map, SymbolLimits lim = {});
    bool running() const;   // a build is pending or running
    void wait();            // blocks until no build is pending or running (tests, scripts)
    std::shared_ptr<const SymbolTable> result() const;
    // result() belongs to the last start() (built for it, or kept by it): nothing pending.
    bool current() const;
    uint64_t generation() const { return generation_.load(); }  // bumps when a build ends
    uint64_t builds() const;  // builds started so far (a start() that kept the result: none)

private:
    struct Request {
        std::shared_ptr<const Snapshot> snap;
        AddressMap map;
        SymbolLimits lim;
        // FileSource::epoch() of every snap->sources entry at start(): an in-place save rewrites a
        // file version under the same pieces, so same_bytes alone cannot see it.
        std::vector<uint64_t> epochs;
    };
    void worker();

    std::thread thread_;
    mutable std::mutex mu_;
    std::condition_variable cv_;   // new request / quit (worker), build finished (wait)
    Request pending_;              // the next build, while has_pending_
    bool has_pending_ = false, busy_ = false, quit_ = false;
    std::atomic<bool> cancel_{false};  // stops the running build (a newer request, quit)
    std::atomic<uint64_t> generation_{0};
    uint64_t requests_ = 0;        // builds started (request ids)
    uint64_t result_request_ = 0;  // the request result_ was built for (0 = none)
    std::shared_ptr<const SymbolTable> result_;
    Request result_for_;           // what result_ was built from (its snapshot: the skip check)
};

}  // namespace hx
