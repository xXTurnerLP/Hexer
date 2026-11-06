#include "core/exe_map.h"

#include <algorithm>
#include <cstring>
#include <initializer_list>
#include <string>
#include <vector>

#include "core/devices.h"
#include "core/document.h"
#include "core/procmem.h"
#include "core/util.h"

namespace hx {
namespace {

// Reads exactly n bytes at off (false past EOF; unreadable bytes read as 0, like everywhere).
bool read_exact(const Document& doc, uint64_t off, uint8_t* dst, size_t n) {
    const uint64_t size = doc.size();
    if (off > size || size - off < n) return false;
    return doc.read(off, dst, n) == n;
}

uint64_t get_le(const uint8_t* p, int n) {
    uint64_t v = 0;
    for (int i = n - 1; i >= 0; --i) v = (v << 8) | p[i];
    return v;
}
uint64_t get_be(const uint8_t* p, int n) {
    uint64_t v = 0;
    for (int i = 0; i < n; ++i) v = (v << 8) | p[i];
    return v;
}

bool add_overflows(uint64_t a, uint64_t b) { return a + b < a; }

bool fail(std::string* err, const std::string& why) {
    if (err) *err = why;
    return false;
}

// Regions must not overlap in file space (non-empty file ranges) nor in address space.
bool check_overlaps(const std::vector<MappedRegion>& rs, std::string* err) {
    for (size_t i = 0; i < rs.size(); ++i) {
        for (size_t j = i + 1; j < rs.size(); ++j) {
            const MappedRegion& a = rs[i];
            const MappedRegion& b = rs[j];
            if (a.file_size && b.file_size && a.offset < b.offset + b.file_size && b.offset < a.offset + a.file_size)
                return fail(err, a.name + " and " + b.name + " overlap in the file");
            if (a.mem_size && b.mem_size && a.address < b.address + b.mem_size && b.address < a.address + a.mem_size)
                return fail(err, a.name + " and " + b.name + " overlap in memory");
        }
    }
    return true;
}

std::string hex_addr(uint64_t v) { return "0x" + fmt_hex(v, 0, true); }

const char* pe_machine_name(uint16_t m) {
    switch (m) {
    case 0x8664: return "x86-64";
    case 0x014C: return "x86";
    case 0xAA64: return "ARM64";
    case 0x01C4: return "ARM";
    default: return "unknown machine";
    }
}

const char* elf_machine_name(uint16_t m) {
    switch (m) {
    case 62: return "x86-64";
    case 3: return "x86";
    case 183: return "AArch64";
    case 40: return "ARM";
    default: return "unknown machine";
    }
}

AddressMap identity_map(const Document& doc, AddressMap::Kind kind, uint64_t base) {
    AddressMap m;
    m.kind = kind;
    m.base = base;
    m.file_size = doc.size();
    if (kind == AddressMap::Manual) m.format = "manual base " + hex_addr(base);
    else if (kind == AddressMap::Process) m.format = "process memory";
    else m.format = "no address map";
    return m;
}

// Process documents: identity, the process's pointer width and its modules as `names`.
AddressMap process_map(const Document& doc) {
    AddressMap m = identity_map(doc, AddressMap::Process, 0);
    const uint32_t pid = doc.process_id();
    m.bits = process_bits(pid);
    std::vector<ModuleInfo> mods;
    process_modules(pid, mods);
    for (const ModuleInfo& mod : mods) {
        if (!mod.size || add_overflows(mod.base, mod.size)) continue;
        MappedRegion r;
        r.offset = r.address = mod.base;
        r.file_size = r.mem_size = mod.size;
        r.name = mod.name;
        m.names.push_back(std::move(r));
    }
    // Entry point: the main module's AddressOfEntryPoint, read from its PE headers in memory.
    const uint64_t main_base = process_start_address(pid);
    for (const MappedRegion& r : m.names) {
        if (r.address != main_base) continue;
        uint8_t dos[64], oh[24 + 20];
        if (!read_exact(doc, main_base, dos, sizeof dos) || dos[0] != 'M' || dos[1] != 'Z') break;
        const uint64_t pe = get_le(dos + 0x3C, 4);
        if (pe < 4 || pe + sizeof oh > r.mem_size || !read_exact(doc, main_base + pe, oh, sizeof oh) ||
            std::memcmp(oh, "PE\0\0", 4) != 0)
            break;
        const uint64_t rva = get_le(oh + 24 + 16, 4);
        if (rva && rva < r.mem_size) {
            m.has_entry = true;
            m.entry = main_base + rva;
        }
        break;
    }
    if (m.bits) m.format += ", " + std::to_string(m.bits) + "-bit";
    m.format += ", " + std::to_string(m.names.size()) + " modules";
    return m;
}

}  // namespace

// ---- AddressMap ----------------------------------------------------------------------------------

bool AddressMap::offset_to_va(uint64_t off, uint64_t& va) const {
    if (kind == None || kind == Manual || kind == Process) {
        if (off > file_size || add_overflows(off, base)) return false;
        va = off + base;
        return true;
    }
    if (const MappedRegion* r = region_at_offset(off)) {
        va = r->address + (off - r->offset);
        return true;
    }
    return false;
}

bool AddressMap::va_to_offset(uint64_t va, uint64_t& off) const {
    if (kind == None || kind == Manual || kind == Process) {
        if (va < base || va - base > file_size) return false;
        off = va - base;
        return true;
    }
    for (const MappedRegion& r : regions)
        if (r.file_size && va >= r.address && va - r.address < r.file_size) {
            off = r.offset + (va - r.address);
            return true;
        }
    return false;
}

const MappedRegion* AddressMap::region_at_offset(uint64_t off) const {
    for (const MappedRegion& r : regions)
        if (r.file_size && off >= r.offset && off - r.offset < r.file_size) return &r;
    return nullptr;
}

std::string AddressMap::section_at_offset(uint64_t off) const {
    for (const MappedRegion& r : names)
        if (r.file_size && off >= r.offset && off - r.offset < r.file_size) return r.name;
    const MappedRegion* r = region_at_offset(off);
    return r ? r->name : std::string();
}

std::string AddressMap::section_at_va(uint64_t va) const {
    for (const MappedRegion& r : names)
        if (r.mem_size && va >= r.address && va - r.address < r.mem_size) return r.name;
    for (const MappedRegion& r : regions)
        if (r.mem_size && va >= r.address && va - r.address < r.mem_size) return r.name;
    return std::string();
}

bool AddressMap::contains_va(uint64_t va) const {
    if (kind == None || kind == Manual || kind == Process) return va >= base && va - base < file_size;
    for (const MappedRegion& r : regions)
        if (r.mem_size && va >= r.address && va - r.address < r.mem_size) return true;
    return false;
}

bool AddressMap::entry_offset(uint64_t& off) const { return has_entry && va_to_offset(entry, off); }

// ---- PE ------------------------------------------------------------------------------------------

bool detect_pe(const Document& doc, AddressMap& out, std::string* err) {
    uint8_t dos[64];
    if (!read_exact(doc, 0, dos, sizeof dos) || dos[0] != 'M' || dos[1] != 'Z') return fail(err, "not a PE file");
    const uint64_t pe = get_le(dos + 0x3C, 4);
    uint8_t coff[24];
    if (pe < 4 || pe > (uint64_t(1) << 28) || !read_exact(doc, pe, coff, sizeof coff))
        return fail(err, "not a PE file (bad e_lfanew)");
    if (std::memcmp(coff, "PE\0\0", 4) != 0) return fail(err, "not a PE file (no PE signature)");
    const uint16_t machine = uint16_t(get_le(coff + 4, 2));
    const uint64_t nsect = get_le(coff + 6, 2);
    const uint64_t opt_size = get_le(coff + 20, 2);
    if (nsect > AddressMap::kMaxSections) return fail(err, "PE: too many sections (" + std::to_string(nsect) + ")");
    if (opt_size < 64) return fail(err, "PE: optional header too small");
    const uint64_t opt = pe + 24;
    uint8_t oh[64];
    if (!read_exact(doc, opt, oh, sizeof oh)) return fail(err, "PE: truncated optional header");
    const uint16_t magic = uint16_t(get_le(oh, 2));
    if (magic != 0x10B && magic != 0x20B) return fail(err, "PE: unknown optional header magic");
    const bool plus = magic == 0x20B;
    const uint64_t entry_rva = get_le(oh + 16, 4);
    const uint64_t image_base = plus ? get_le(oh + 24, 8) : get_le(oh + 28, 4);
    const uint64_t sect_align = get_le(oh + 32, 4);
    const uint64_t size_headers = get_le(oh + 60, 4);
    const uint64_t table = opt + opt_size;
    const uint64_t size = doc.size();
    if (table > size || (size - table) / 40 < nsect) return fail(err, "PE: truncated section table");

    AddressMap m;
    m.kind = AddressMap::Pe;
    m.base = image_base;
    m.file_size = size;
    m.bits = plus ? 64 : 32;
    m.format = std::string(plus ? "PE32+ " : "PE32 ") + pe_machine_name(machine);
    uint64_t first_raw = size, first_va = UINT64_MAX;
    for (uint64_t i = 0; i < nsect; ++i) {
        uint8_t s[40];
        if (!read_exact(doc, table + i * 40, s, sizeof s)) return fail(err, "PE: truncated section table");
        MappedRegion r;
        size_t nlen = 0;
        while (nlen < 8 && s[nlen]) ++nlen;
        r.name.assign(reinterpret_cast<const char*>(s), nlen);
        for (char& c : r.name)
            if (uint8_t(c) < 0x20 || uint8_t(c) >= 0x7F) c = '?';
        if (r.name.empty()) r.name = "section" + std::to_string(i);
        const uint64_t vsize = get_le(s + 8, 4);
        const uint64_t rva = get_le(s + 12, 4);
        const uint64_t raw_size = get_le(s + 16, 4);
        const uint64_t raw_ptr = get_le(s + 20, 4);
        const uint64_t chars = get_le(s + 36, 4);
        uint64_t mapped = raw_size;
        if (vsize) {
            uint64_t vext = vsize;
            if (sect_align > 1) vext = (vsize + sect_align - 1) / sect_align * sect_align;  // < 2^33
            mapped = std::min(mapped, vext);
        }
        if (raw_ptr >= size) mapped = 0;                       // truncated file: no bytes left
        else mapped = std::min(mapped, size - raw_ptr);
        r.offset = raw_ptr;
        r.file_size = mapped;
        if (add_overflows(image_base, rva)) return fail(err, "PE: section " + r.name + " address overflows");
        r.address = image_base + rva;
        r.mem_size = std::max(vsize ? vsize : raw_size, mapped);
        if (add_overflows(r.address, r.mem_size)) return fail(err, "PE: section " + r.name + " address overflows");
        r.exec = (chars & 0x20000000u) || (chars & 0x20u);
        if (r.file_size) first_raw = std::min(first_raw, r.offset);
        if (r.mem_size) first_va = std::min(first_va, rva);
        m.regions.push_back(std::move(r));
    }
    // The headers are mapped at ImageBase too (up to the first section's bytes / address).
    uint64_t hdr = std::min({size_headers, first_raw, size});
    if (first_va != UINT64_MAX) hdr = std::min(hdr, first_va);
    if (hdr) {
        MappedRegion h;
        h.offset = 0;
        h.file_size = h.mem_size = hdr;
        h.address = image_base;
        h.name = "(headers)";
        if (add_overflows(image_base, hdr)) return fail(err, "PE: image base overflows");
        m.regions.insert(m.regions.begin(), std::move(h));
    }
    if (!check_overlaps(m.regions, err)) {
        if (err) *err = "PE: " + *err;
        return false;
    }
    std::stable_sort(m.regions.begin(), m.regions.end(),
                     [](const MappedRegion& a, const MappedRegion& b) { return a.offset < b.offset; });
    if (entry_rva && !add_overflows(image_base, entry_rva)) {
        m.has_entry = true;
        m.entry = image_base + entry_rva;
    }
    out = std::move(m);
    return true;
}

// ---- PE image in memory --------------------------------------------------------------------------

bool detect_pe_image(const Snapshot& snap, uint64_t base, AddressMap& out, std::string* err) {
    const uint64_t size = snap.size();
    auto rd = [&](uint64_t rva, uint8_t* dst, size_t n) {
        return !add_overflows(base, rva) && base + rva <= size && size - (base + rva) >= n &&
               snap.read_valid(base + rva, dst, n) == n;
    };
    const std::string where = "no PE image at " + hex_addr(base);
    uint8_t dos[64];
    if (!rd(0, dos, sizeof dos) || dos[0] != 'M' || dos[1] != 'Z') return fail(err, where);
    const uint64_t pe = get_le(dos + 0x3C, 4);
    uint8_t coff[24];
    if (pe < 4 || pe > (uint64_t(1) << 20) || !rd(pe, coff, sizeof coff) || std::memcmp(coff, "PE\0\0", 4) != 0)
        return fail(err, where + " (no PE signature)");
    const uint16_t machine = uint16_t(get_le(coff + 4, 2));
    const uint64_t nsect = get_le(coff + 6, 2);
    const uint64_t opt_size = get_le(coff + 20, 2);
    if (nsect > AddressMap::kMaxSections) return fail(err, "PE image: too many sections (" + std::to_string(nsect) + ")");
    uint8_t oh[64];
    if (opt_size < 64 || !rd(pe + 24, oh, sizeof oh)) return fail(err, "PE image: truncated optional header");
    const uint16_t magic = uint16_t(get_le(oh, 2));
    if (magic != 0x10B && magic != 0x20B) return fail(err, "PE image: unknown optional header magic");
    const bool plus = magic == 0x20B;
    const uint64_t entry_rva = get_le(oh + 16, 4);
    const uint64_t sect_align = get_le(oh + 32, 4);
    const uint64_t image_size = get_le(oh + 56, 4);
    const uint64_t size_headers = get_le(oh + 60, 4);
    if (!image_size || add_overflows(base, image_size) || base + image_size > size)
        return fail(err, "PE image: SizeOfImage out of range");
    const uint64_t table = pe + 24 + opt_size;
    if (table + nsect * 40 > image_size) return fail(err, "PE image: section table outside the image");

    AddressMap m;
    m.kind = AddressMap::Pe;
    m.in_memory = true;
    m.base = base;
    m.file_size = size;
    m.bits = plus ? 64 : 32;
    m.format = std::string(plus ? "PE32+ " : "PE32 ") + pe_machine_name(machine) + " image in memory";
    uint64_t first_rva = image_size;
    for (uint64_t i = 0; i < nsect; ++i) {
        uint8_t s[40];
        if (!rd(table + i * 40, s, sizeof s)) return fail(err, "PE image: unreadable section table");
        MappedRegion r;
        size_t nlen = 0;
        while (nlen < 8 && s[nlen]) ++nlen;
        r.name.assign(reinterpret_cast<const char*>(s), nlen);
        for (char& c : r.name)
            if (uint8_t(c) < 0x20 || uint8_t(c) >= 0x7F) c = '?';
        if (r.name.empty()) r.name = "section" + std::to_string(i);
        const uint64_t vsize = get_le(s + 8, 4);
        const uint64_t rva = get_le(s + 12, 4);
        const uint64_t raw_size = get_le(s + 16, 4);
        const uint64_t chars = get_le(s + 36, 4);
        uint64_t ext = vsize ? vsize : raw_size;
        if (sect_align > 1) ext = (ext + sect_align - 1) / sect_align * sect_align;  // < 2^33
        if (rva >= image_size) return fail(err, "PE image: section " + r.name + " outside SizeOfImage");
        ext = std::min(ext, image_size - rva);
        if (!ext) continue;
        r.offset = r.address = base + rva;
        r.file_size = r.mem_size = ext;
        r.exec = (chars & 0x20000000u) || (chars & 0x20u);
        first_rva = std::min(first_rva, rva);
        m.regions.push_back(std::move(r));
    }
    const uint64_t hdr = std::min(size_headers ? size_headers : first_rva, first_rva);
    if (hdr) {
        MappedRegion h;
        h.offset = h.address = base;
        h.file_size = h.mem_size = hdr;
        h.name = "(headers)";
        m.regions.insert(m.regions.begin(), std::move(h));
    }
    if (!check_overlaps(m.regions, err)) {
        if (err) *err = "PE image: " + *err;
        return false;
    }
    std::stable_sort(m.regions.begin(), m.regions.end(),
                     [](const MappedRegion& a, const MappedRegion& b) { return a.offset < b.offset; });
    if (entry_rva && entry_rva < image_size) {
        m.has_entry = true;
        m.entry = base + entry_rva;
    }
    out = std::move(m);
    return true;
}

// ---- ELF -----------------------------------------------------------------------------------------

bool detect_elf(const Document& doc, AddressMap& out, std::string* err) {
    uint8_t eh[64];
    if (!read_exact(doc, 0, eh, 16) || std::memcmp(eh, "\x7F" "ELF", 4) != 0) return fail(err, "not an ELF file");
    const bool is64 = eh[4] == 2;
    if (eh[4] != 1 && eh[4] != 2) return fail(err, "ELF: unknown class");
    if (eh[5] != 1 && eh[5] != 2) return fail(err, "ELF: unknown byte order");
    const bool be = eh[5] == 2;
    if (!read_exact(doc, 0, eh, is64 ? 64 : 52)) return fail(err, "ELF: truncated header");
    auto get = [be](const uint8_t* p, int n) { return be ? get_be(p, n) : get_le(p, n); };
    const uint16_t machine = uint16_t(get(eh + 18, 2));
    const uint64_t entry = is64 ? get(eh + 24, 8) : get(eh + 24, 4);
    const uint64_t phoff = is64 ? get(eh + 32, 8) : get(eh + 28, 4);
    const uint64_t shoff = is64 ? get(eh + 40, 8) : get(eh + 32, 4);
    const uint64_t phentsize = get(eh + (is64 ? 54 : 42), 2);
    const uint64_t phnum = get(eh + (is64 ? 56 : 44), 2);
    const uint64_t shentsize = get(eh + (is64 ? 58 : 46), 2);
    const uint64_t shnum = get(eh + (is64 ? 60 : 48), 2);
    const uint64_t shstrndx = get(eh + (is64 ? 62 : 50), 2);
    const uint64_t ph_need = is64 ? 56 : 32;
    const uint64_t sh_need = is64 ? 64 : 40;
    const uint64_t size = doc.size();
    if (phnum == 0) return fail(err, "ELF: no program headers");
    if (phnum > AddressMap::kMaxSegments) return fail(err, "ELF: too many program headers (" + std::to_string(phnum) + ")");
    if (phentsize < ph_need) return fail(err, "ELF: program header entries too small");
    if (phoff > size || (size - phoff) / phentsize < phnum) return fail(err, "ELF: truncated program headers");

    AddressMap m;
    m.kind = AddressMap::Elf;
    m.file_size = size;
    m.bits = is64 ? 64 : 32;
    m.format = std::string(is64 ? "ELF64 " : "ELF32 ") + elf_machine_name(machine);
    int load = 0;
    for (uint64_t i = 0; i < phnum; ++i) {
        uint8_t p[56];
        if (!read_exact(doc, phoff + i * phentsize, p, size_t(ph_need))) return fail(err, "ELF: truncated program headers");
        if (get(p, 4) != 1) continue;  // PT_LOAD only
        MappedRegion r;
        uint64_t flags, filesz;
        if (is64) {
            flags = get(p + 4, 4);
            r.offset = get(p + 8, 8);
            r.address = get(p + 16, 8);
            filesz = get(p + 32, 8);
            r.mem_size = get(p + 40, 8);
        } else {
            r.offset = get(p + 4, 4);
            r.address = get(p + 8, 4);
            filesz = get(p + 16, 4);
            r.mem_size = get(p + 20, 4);
            flags = get(p + 24, 4);
        }
        if (add_overflows(r.offset, filesz) || add_overflows(r.address, std::max(filesz, r.mem_size)))
            return fail(err, "ELF: segment " + std::to_string(i) + " overflows");
        r.mem_size = std::max(r.mem_size, filesz);
        r.file_size = r.offset >= size ? 0 : std::min(filesz, size - r.offset);  // truncated file
        r.exec = (flags & 1) != 0;
        r.name = "LOAD" + std::to_string(load++);
        m.regions.push_back(std::move(r));
    }
    if (m.regions.empty()) return fail(err, "ELF: no loadable segments");
    if (!check_overlaps(m.regions, err)) {
        if (err) *err = "ELF: " + *err;
        return false;
    }
    std::stable_sort(m.regions.begin(), m.regions.end(),
                     [](const MappedRegion& a, const MappedRegion& b) { return a.offset < b.offset; });

    // Section names (optional: malformed section headers only lose the names).
    if (shnum && shnum <= AddressMap::kMaxSections && shentsize >= sh_need && shstrndx < shnum && shoff <= size &&
        (size - shoff) / shentsize >= shnum) {
        auto read_sh = [&](uint64_t i, uint8_t* s) { return read_exact(doc, shoff + i * shentsize, s, size_t(sh_need)); };
        uint8_t s[64];
        uint64_t str_off = 0, str_size = 0;
        if (read_sh(shstrndx, s)) {
            str_off = is64 ? get(s + 24, 8) : get(s + 16, 4);
            str_size = is64 ? get(s + 32, 8) : get(s + 20, 4);
            if (str_off > size || str_size > size - str_off) str_size = 0;
        }
        for (uint64_t i = 1; str_size && i < shnum; ++i) {
            if (!read_sh(i, s)) break;
            const uint64_t name = get(s, 4);
            const uint64_t type = get(s + 4, 4);
            const uint64_t flags = is64 ? get(s + 8, 8) : get(s + 8, 4);
            if (!(flags & 2) || name >= str_size) continue;  // SHF_ALLOC only
            // .tbss (NOBITS + SHF_TLS) is a per-thread template: its sh_addr range overlaps the
            // sections after it (.init_array, .data.rel.ro ...) without occupying it.
            if (type == 8 && (flags & 0x400)) continue;
            MappedRegion r;
            r.address = is64 ? get(s + 16, 8) : get(s + 12, 4);
            r.offset = is64 ? get(s + 24, 8) : get(s + 16, 4);
            r.mem_size = is64 ? get(s + 32, 8) : get(s + 20, 4);
            if (add_overflows(r.address, r.mem_size) || add_overflows(r.offset, r.mem_size)) continue;
            r.file_size = type == 8 ? 0 : r.mem_size;  // SHT_NOBITS (.bss) has no file bytes
            r.exec = (flags & 4) != 0;
            char nb[64] = {};
            const uint64_t n = std::min<uint64_t>(sizeof nb - 1, str_size - name);
            if (!read_exact(doc, str_off + name, reinterpret_cast<uint8_t*>(nb), size_t(n))) continue;
            r.name = nb;  // stops at the NUL
            if (r.name.empty()) continue;
            m.names.push_back(std::move(r));
        }
    }
    if (entry) {
        m.has_entry = true;
        m.entry = entry;
    }
    out = std::move(m);
    return true;
}

// ---- detection -----------------------------------------------------------------------------------

AddressMap detect_address_map(const Document& doc, std::string* err) {
    if (err) err->clear();
    if (doc.target() == SourceKind::Process) return process_map(doc);
    AddressMap m;
    std::string e;
    if (detect_pe(doc, m, &e)) return m;
    if (err && e.rfind("not a", 0) != 0) *err = e;
    if (detect_elf(doc, m, &e)) return m;
    if (err && e.rfind("not a", 0) != 0) *err = e;
    return identity_map(doc, AddressMap::None, 0);
}

AddressMap manual_address_map(const Document& doc, uint64_t base) { return identity_map(doc, AddressMap::Manual, base); }

AddressMap no_address_map(const Document& doc) { return identity_map(doc, AddressMap::None, 0); }

}  // namespace hx
