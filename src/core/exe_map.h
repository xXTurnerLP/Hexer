#pragma once
// File offset <-> virtual address mapping of an executable image, for the Disassembly panel
// (addresses, RIP-relative / branch targets) and doc:disasm.
//
//   * PE (PE32 / PE32+): DOS "MZ" -> e_lfanew -> "PE\0\0", the optional header's ImageBase /
//     AddressOfEntryPoint / SizeOfHeaders and the section table. Each section with raw data maps
//     [PointerToRawData, + min(SizeOfRawData, VirtualSize rounded up to SectionAlignment)) to
//     ImageBase + VirtualAddress; the headers map [0, SizeOfHeaders) to ImageBase ("(headers)").
//   * ELF (ELF32 / ELF64, either byte order): PT_LOAD program headers map [p_offset, + p_filesz)
//     to p_vaddr ("LOAD0" ...); section headers (SHF_ALLOC, not NOBITS) only provide names
//     (".text"), looked up by offset or address. The entry point is e_entry.
//   * Manual: VA = offset + base. None: VA = offset. Process documents: VA = offset (identity;
//     their offsets already are virtual addresses); `names` lists the loaded modules (one entry
//     per module: offset = address = base, sizes = the module size, name "KERNEL32.DLL"; from
//     process_modules, core/devices.h), so section_at_* name the module and build_symbols reads
//     each module's in-memory PE headers; `bits` is the process's pointer width.
//   * PE image in memory (detect_pe_image, for a module of a process document): the headers are
//     read at the load address and every section is mapped by RVA - offset == address == load
//     address + VirtualAddress, PointerToRawData / SizeOfRawData are ignored (a loaded image is
//     laid out by RVA); kind Pe with in_memory = true and base = the load address (not the
//     header's ImageBase).
//
// Detection reads only the headers through Document::read (bounded: at most kMaxSections /
// kMaxSegments table entries, each read checked against the document size). A malformed header
// (truncated, absurd counts or sizes, regions overlapping in file or address space, address
// overflow) is rejected - detect_pe / detect_elf return false with a reason - and never reads out
// of range or loops.
#include <cstdint>
#include <string>
#include <vector>

namespace hx {

class Document;
class Snapshot;

struct MappedRegion {
    uint64_t offset = 0;     // file offset of the first byte
    uint64_t file_size = 0;  // bytes backed by the file
    uint64_t address = 0;    // virtual address of the first byte
    uint64_t mem_size = 0;   // size in memory (>= file_size; the rest is zero-filled, e.g. .bss)
    std::string name;        // ".text", "(headers)", "LOAD1"
    bool exec = false;       // code (PE IMAGE_SCN_MEM_EXECUTE / CNT_CODE, ELF PF_X)
};

struct AddressMap {
    enum Kind : uint8_t { None, Manual, Pe, Elf, Process };
    static constexpr size_t kMaxSections = 1024;  // PE section table / ELF section headers
    static constexpr size_t kMaxSegments = 1024;  // ELF program headers

    Kind kind = None;
    uint64_t base = 0;            // Manual: VA = offset + base; Pe: ImageBase; else 0
    uint64_t file_size = 0;       // document size at detection (None / Manual / Process range)
    std::vector<MappedRegion> regions;  // Pe / Elf: sorted by offset, non-overlapping
    std::vector<MappedRegion> names;    // Elf: section names (by offset / address); Pe: unused
    bool has_entry = false;
    uint64_t entry = 0;           // virtual address of the entry point
    int bits = 0;                 // 64 / 32 from the header (0 = unknown): the natural disasm mode
    std::string format;           // "PE32+ x86-64", "ELF64 x86-64", "manual base 0x400000", ...
    bool in_memory = false;       // Pe: an image mapped in memory (detect_pe_image), offset == VA

    // Virtual address of file offset `off`. Pe / Elf: false outside every region. None / Manual /
    // Process: always (off + base), false only past file_size or on overflow.
    bool offset_to_va(uint64_t off, uint64_t& va) const;
    // File offset of virtual address `va`; false when it is not backed by the file (outside the
    // image, .bss, before base, past file_size).
    bool va_to_offset(uint64_t va, uint64_t& off) const;
    // Name of the section / segment containing file offset `off` / address `va` ("" if none;
    // a .bss address has a name although it has no file offset). None / Manual / Process: "".
    std::string section_at_offset(uint64_t off) const;
    std::string section_at_va(uint64_t va) const;
    // `va` lies inside the mapped image (a region's memory extent, .bss included). None / Manual /
    // Process: inside [base, base + file_size).
    bool contains_va(uint64_t va) const;
    // The region holding file offset `off`, or nullptr (Pe / Elf only).
    const MappedRegion* region_at_offset(uint64_t off) const;
    // File offset of the entry point (false: none, or not backed by the file).
    bool entry_offset(uint64_t& off) const;
};

// Header parsers. True + `out` filled on success; false (out untouched) + *err when the document
// is not that format or the header is malformed ("not a PE file", "section 3 overlaps ...").
bool detect_pe(const Document& doc, AddressMap& out, std::string* err = nullptr);
bool detect_elf(const Document& doc, AddressMap& out, std::string* err = nullptr);
// The PE image the loader mapped at `base` in `snap` (a process document's bytes: offset = virtual
// address). Bounded like detect_pe (headers and the section table only, read with read_valid so an
// unreadable page fails); false + *err when there is no valid PE header at `base`, SizeOfImage
// runs past the snapshot or the sections overlap / lie outside SizeOfImage.
bool detect_pe_image(const Snapshot& snap, uint64_t base, AddressMap& out, std::string* err = nullptr);
// Process documents -> identity (Process, with the module list: one quick OS query); else PE, then
// ELF; else None. Never fails. When a
// header looked like PE / ELF but was rejected, *err says why (the map is None then).
AddressMap detect_address_map(const Document& doc, std::string* err = nullptr);
AddressMap manual_address_map(const Document& doc, uint64_t base);
AddressMap no_address_map(const Document& doc);

}  // namespace hx
