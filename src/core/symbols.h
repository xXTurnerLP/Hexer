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
//   * Anything else (None / Manual maps for PE / ELF executables, process memory): empty.
//
// Bounded and checked: every read is range-checked against the snapshot, counts are capped
// (kMaxSymbols in total, kMaxName bytes per name, kMaxNameBytes of names, kMaxModules import
// descriptors), a malformed table only loses its own entries, and the build stops after
// SymbolLimits::max_ms (truncated = true). Reads go through a Snapshot so a build can run on a
// worker thread (SymbolJob) while the UI keeps the previous table.
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
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

    bool empty() const { return symbols.empty() && forwarders.empty(); }
    // The first symbol at exactly `va` (exports before functions, objects, imports), or nullptr.
    const Symbol* at(uint64_t va) const;
    // The closest non-import symbol at or before `va` (*delta = va - its address), or nullptr.
    const Symbol* nearest(uint64_t va, uint64_t* delta = nullptr) const;
    // Sorts / dedupes `symbols` and builds the lookup index (build_symbols calls it).
    void finalize();

private:
    std::vector<uint32_t> code_;     // indices of the non-import symbols (address order)
};

// Builds the symbols of `snap` (the document's bytes) under `map` (detect_address_map of the same
// document). `cancel` (may be null) stops it early. Never fails: unknown formats give an empty table.
SymbolTable build_symbols(const Snapshot& snap, const AddressMap& map, const SymbolLimits& lim = {},
                          const std::atomic<bool>* cancel = nullptr);

// Background build (one at a time). start() cancels and joins a previous run (it stops within one
// table entry), then builds on a worker thread; result() is the last finished table (null before
// the first one finishes) and stays until the next run finishes, so the UI never shows an empty
// table while rebuilding after an edit.
class SymbolJob {
public:
    SymbolJob() = default;
    ~SymbolJob();
    SymbolJob(const SymbolJob&) = delete;
    SymbolJob& operator=(const SymbolJob&) = delete;

    void start(std::shared_ptr<const Snapshot> snap, AddressMap map, SymbolLimits lim = {});
    bool running() const { return running_.load(); }
    void wait();  // blocks until the current run finished (tests, scripts)
    std::shared_ptr<const SymbolTable> result() const;
    uint64_t generation() const { return generation_.load(); }  // bumps when a run finishes

private:
    void stop();
    std::thread thread_;
    std::atomic<bool> cancel_{false};
    std::atomic<bool> running_{false};
    std::atomic<uint64_t> generation_{0};
    mutable std::mutex mu_;
    std::shared_ptr<const SymbolTable> result_;
};

}  // namespace hx
