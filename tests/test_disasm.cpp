// Disassembly (core/disasm.h, Zydis) and executable address maps (core/exe_map.h).
#include <doctest/doctest.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <memory>
#include <random>
#include <string>
#include <system_error>
#include <vector>

#include "core/disasm.h"
#include "core/document.h"
#include "core/exe_map.h"
#include "core/session.h"
#include "core/symbols.h"
#include "imgui.h"
#include "script/script_engine.h"
#include "ui/panel_disasm.h"
#include "symbol_fixture.h"

using namespace hx;

namespace {

using Bytes = std::vector<uint8_t>;

std::unique_ptr<Document> doc_of(const Bytes& b) { return Document::create_from_bytes("t", b.data(), b.size()); }

Insn one(const Bytes& b, uint64_t address, DisasmOptions opt = {}) {
    Insn i;
    disasm_one(b.data(), b.size(), address, opt, i);
    return i;
}

void put(Bytes& b, size_t off, uint64_t v, int n) {
    if (b.size() < off + size_t(n)) b.resize(off + size_t(n));
    for (int i = 0; i < n; ++i) b[off + size_t(i)] = uint8_t(v >> (8 * i));
}

void put_str(Bytes& b, size_t off, const char* s) {
    const size_t n = std::strlen(s);
    if (b.size() < off + n) b.resize(off + n);
    std::memcpy(b.data() + off, s, n);
}

// Minimal PE32+: headers 0x200, .text raw [0x200, 0x400) at RVA 0x1000 (VirtualSize 0x150),
// .data raw [0x400, 0x600) at RVA 0x2000 (VirtualSize 0x1000: the rest is .bss), entry RVA 0x1010.
Bytes make_pe() {
    Bytes b(0x600, 0);
    put_str(b, 0, "MZ");
    put(b, 0x3C, 0x40, 4);
    put_str(b, 0x40, "PE");
    put(b, 0x44, 0x8664, 2);  // Machine
    put(b, 0x46, 2, 2);       // NumberOfSections
    put(b, 0x54, 0xF0, 2);    // SizeOfOptionalHeader
    put(b, 0x56, 0x22, 2);
    const size_t opt = 0x58;
    put(b, opt + 0, 0x20B, 2);              // PE32+
    put(b, opt + 16, 0x1010, 4);            // AddressOfEntryPoint
    put(b, opt + 24, 0x140000000ull, 8);    // ImageBase
    put(b, opt + 32, 0x1000, 4);            // SectionAlignment
    put(b, opt + 36, 0x200, 4);             // FileAlignment
    put(b, opt + 56, 0x3000, 4);            // SizeOfImage
    put(b, opt + 60, 0x200, 4);             // SizeOfHeaders
    const size_t sec = opt + 0xF0;
    put_str(b, sec, ".text");
    put(b, sec + 8, 0x150, 4);
    put(b, sec + 12, 0x1000, 4);
    put(b, sec + 16, 0x200, 4);
    put(b, sec + 20, 0x200, 4);
    put(b, sec + 36, 0x60000020, 4);
    put_str(b, sec + 40, ".data");
    put(b, sec + 48, 0x1000, 4);
    put(b, sec + 52, 0x2000, 4);
    put(b, sec + 56, 0x200, 4);
    put(b, sec + 60, 0x400, 4);
    put(b, sec + 76, 0xC0000040u, 4);
    // Entry point code: mov rax, [rip+0x2A]; call rel32; ret
    const Bytes code = {0x48, 0x8B, 0x05, 0x2A, 0x00, 0x00, 0x00, 0xE8, 0x00, 0x01, 0x00, 0x00, 0xC3};
    std::memcpy(b.data() + 0x210, code.data(), code.size());
    return b;
}

// Minimal ELF64 LE: PT_LOAD [0, 0x200) -> 0x400000 (r), PT_LOAD [0x200, 0x300) -> 0x401000 (r-x),
// section headers .text / .bss / .shstrtab, entry 0x401020.
Bytes make_elf() {
    Bytes b(0x420, 0);
    put_str(b, 0, "\x7F" "ELF");
    b[4] = 2;  // ELFCLASS64
    b[5] = 1;  // little endian
    b[6] = 1;
    put(b, 16, 2, 2);          // ET_EXEC
    put(b, 18, 62, 2);         // EM_X86_64
    put(b, 20, 1, 4);
    put(b, 24, 0x401020, 8);   // e_entry
    put(b, 32, 64, 8);         // e_phoff
    put(b, 40, 0x300, 8);      // e_shoff
    put(b, 52, 64, 2);
    put(b, 54, 56, 2);         // e_phentsize
    put(b, 56, 2, 2);          // e_phnum
    put(b, 58, 64, 2);         // e_shentsize
    put(b, 60, 4, 2);          // e_shnum
    put(b, 62, 3, 2);          // e_shstrndx
    auto ph = [&](size_t at, uint32_t flags, uint64_t off, uint64_t va, uint64_t filesz, uint64_t memsz) {
        put(b, at, 1, 4);
        put(b, at + 4, flags, 4);
        put(b, at + 8, off, 8);
        put(b, at + 16, va, 8);
        put(b, at + 24, va, 8);
        put(b, at + 32, filesz, 8);
        put(b, at + 40, memsz, 8);
        put(b, at + 48, 0x1000, 8);
    };
    ph(64, 4, 0, 0x400000, 0x200, 0x200);
    ph(64 + 56, 5, 0x200, 0x401000, 0x100, 0x100);
    auto sh = [&](size_t i, uint32_t name, uint32_t type, uint64_t flags, uint64_t addr, uint64_t off, uint64_t size) {
        const size_t at = 0x300 + i * 64;
        put(b, at, name, 4);
        put(b, at + 4, type, 4);
        put(b, at + 8, flags, 8);
        put(b, at + 16, addr, 8);
        put(b, at + 24, off, 8);
        put(b, at + 32, size, 8);
    };
    const char strtab[] = "\0.text\0.bss\0.shstrtab";  // .text @1, .bss @7, .shstrtab @12
    std::memcpy(b.data() + 0x400, strtab, sizeof strtab);
    sh(1, 1, 1, 6, 0x401000, 0x200, 0x100);         // .text: PROGBITS, ALLOC | EXECINSTR
    sh(2, 7, 8, 3, 0x402000, 0x300, 0x100);         // .bss: NOBITS, ALLOC | WRITE
    sh(3, 12, 3, 0, 0, 0x400, sizeof strtab);       // .shstrtab
    const Bytes code = {0x55, 0x48, 0x89, 0xE5, 0xC3};
    std::memcpy(b.data() + 0x220, code.data(), code.size());
    return b;
}

// A realistic instruction stream (lengths 1..7) repeated; returns the start of every instruction.
Bytes make_stream(int reps, std::vector<uint64_t>& starts) {
    const std::vector<Bytes> insns = {
        {0x55},                                      // push rbp
        {0x48, 0x89, 0xE5},                          // mov rbp, rsp
        {0x48, 0x83, 0xEC, 0x20},                    // sub rsp, 0x20
        {0x48, 0x8B, 0x05, 0x2A, 0x00, 0x00, 0x00},  // mov rax, [rip+0x2A]
        {0xE8, 0x00, 0x01, 0x00, 0x00},              // call
        {0x85, 0xC0},                                // test eax, eax
        {0x74, 0x05},                                // jz
        {0x48, 0x8D, 0x0D, 0xF9, 0xFF, 0xFF, 0xFF},  // lea rcx, [rip-7]
        {0x89, 0x44, 0x24, 0x08},                    // mov [rsp+8], eax
        {0xC3},                                      // ret
        {0xCC},                                      // int3
    };
    Bytes b;
    for (int r = 0; r < reps; ++r)
        for (const Bytes& i : insns) {
            starts.push_back(b.size());
            b.insert(b.end(), i.begin(), i.end());
        }
    return b;
}

}  // namespace

// ---- single instructions ---------------------------------------------------------------------------

TEST_CASE("disasm: RIP-relative mov / lea resolve their target") {
    Insn i = one({0x48, 0x8B, 0x05, 0x2A, 0x00, 0x00, 0x00}, 0x140001000);
    CHECK(i.valid);
    CHECK(i.length == 7);
    CHECK(i.text == "mov rax, qword ptr [rip+0x2a]  ; 0x140001031");
    CHECK(i.has_target);
    CHECK(i.target == 0x140001031);
    CHECK(i.flow == Insn::None);

    i = one({0x48, 0x8D, 0x0D, 0xF9, 0xFF, 0xFF, 0xFF}, 0x1000);
    CHECK(i.text == "lea rcx, [rip-0x07]  ; 0x1000");
    CHECK(i.target == 0x1000);

    DisasmOptions up;
    up.uppercase = true;
    i = one({0x48, 0x8B, 0x05, 0x2A, 0x00, 0x00, 0x00}, 0x140001000, up);
    CHECK(i.text == "MOV RAX, QWORD PTR [RIP+0x2A]  ; 0x140001031");
}

TEST_CASE("disasm: branches, calls, returns, interrupts") {
    Insn i = one({0xE8, 0x00, 0x01, 0x00, 0x00}, 0x1000);
    CHECK(i.text == "call 0x1105");
    CHECK(i.flow == Insn::Call);
    CHECK(i.has_target);
    CHECK(i.target == 0x1105);

    i = one({0x74, 0xF0}, 0x2010);  // jz rel8 backwards
    CHECK(i.flow == Insn::CondJump);
    CHECK(i.target == 0x2002);
    CHECK(i.text == "jz 0x2002");

    i = one({0xEB, 0xFE}, 0x3000);  // jmp $
    CHECK(i.flow == Insn::Jump);
    CHECK(i.target == 0x3000);

    i = one({0xC3}, 0);
    CHECK(i.text == "ret");
    CHECK(i.flow == Insn::Ret);
    CHECK_FALSE(i.has_target);

    i = one({0xCC}, 0);
    CHECK(i.text == "int3");
    CHECK(i.flow == Insn::Int);

    i = one({0x0F, 0x05}, 0);
    CHECK(i.text == "syscall");
    CHECK(i.flow == Insn::Int);
    CHECK(i.length == 2);

    i = one({0xFF, 0x15, 0x10, 0x00, 0x00, 0x00}, 0x1000);  // call [rip+0x10] (IAT slot)
    CHECK(i.flow == Insn::Call);
    CHECK(i.target == 0x1016);
}

TEST_CASE("disasm: invalid bytes, AVX, 32-bit mode") {
    Insn i;
    const uint8_t bad[] = {0x06, 0x90};  // push es: invalid in 64-bit mode
    CHECK_FALSE(disasm_one(bad, sizeof bad, 0x10, {}, i));
    CHECK_FALSE(i.valid);
    CHECK(i.length == 1);
    CHECK(i.text == "db 0x06");
    CHECK_FALSE(disasm_one(bad, 0, 0x10, {}, i));
    CHECK(i.length == 0);

    i = one({0xC5, 0xFC, 0x28, 0xC1}, 0);  // VEX.256
    CHECK(i.valid);
    CHECK(i.text == "vmovaps ymm0, ymm1");
    i = one({0x62, 0xF1, 0x7C, 0x48, 0x28, 0xC1}, 0);  // EVEX (AVX-512)
    CHECK(i.text == "vmovaps zmm0, zmm1");

    DisasmOptions x86;
    x86.mode = DisasmMode::X86;
    i = one({0x06}, 0, x86);
    CHECK(i.valid);
    CHECK(i.text == "push es");
    i = one({0x8B, 0x05, 0x00, 0x10, 0x40, 0x00}, 0x401000, x86);  // absolute memory operand
    CHECK(i.text == "mov eax, dword ptr [0x401000]");
    CHECK(i.has_target);
    CHECK(i.target == 0x401000);
    i = one({0xE8, 0xFB, 0xFF, 0xFF, 0xFF}, 0x401000, x86);
    CHECK(i.text == "call 0x401000");
    CHECK(i.target == 0x401000);
    i = one({0xE8, 0x00, 0x00, 0x00, 0x00}, 0xFFFFFFF0u, x86);  // wraps at 4 GiB
    CHECK(i.target == 0xFFFFFFF5u);

    DisasmOptions att;
    att.syntax = DisasmSyntax::Att;
    i = one({0x48, 0x89, 0xC8}, 0, att);
    CHECK(i.text == "mov %rcx, %rax");

    i = one({0x48, 0x8B, 0x05, 0x2A, 0x00, 0x00, 0x00}, 0);
    CHECK(insn_bytes_hex(i) == "48 8B 05 2A 00 00 00");
    CHECK(std::string(insn_flow_name(Insn::CondJump)) == "jcc");
}

// ---- ranges over documents -------------------------------------------------------------------------

TEST_CASE("disasm_range: matches disasm_one across chunk boundaries") {
    std::vector<uint64_t> starts;
    Bytes b = {0x90};  // shift every instruction by one so some straddle the 64 KiB chunk edge
    {
        Bytes s = make_stream(7000, starts);  // ~260 KB
        b.insert(b.end(), s.begin(), s.end());
        for (uint64_t& st : starts) ++st;
        starts.insert(starts.begin(), 0);
    }
    auto doc = doc_of(b);
    std::vector<Insn> out;
    const AddressMap none = no_address_map(*doc);
    disasm_range(*doc, 0, 20000, none, {}, out);
    REQUIRE(out.size() == 20000);
    for (size_t k = 0; k < out.size(); ++k) {
        REQUIRE(out[k].offset == starts[k]);
        Insn ref;
        disasm_one(b.data() + starts[k], b.size() - size_t(starts[k]), starts[k], {}, ref);
        REQUIRE(out[k].text == ref.text);
        REQUIRE(out[k].length == ref.length);
        CHECK(out[k].address == starts[k]);
    }

    // Stops at EOF; invalid bytes are 1-byte "db" rows; the map supplies addresses.
    auto small = doc_of({0x06, 0x90, 0x48, 0x89});
    out.clear();
    const AddressMap manual = manual_address_map(*small, 0x400000);
    disasm_range(*small, 0, 100, manual, {}, out);
    REQUIRE(out.size() == 4);  // db 0x06, nop, then a truncated "48 89" = two db rows
    CHECK(out[0].text == "db 0x06");
    CHECK(out[1].text == "nop");
    CHECK(out[1].address == 0x400001);
    CHECK(out[2].text == "db 0x48");
    CHECK(out[3].offset == 3);
    out.clear();
    disasm_range(*small, 4, 10, manual, {}, out);
    CHECK(out.empty());
}

TEST_CASE("disasm_sync_back: resynchronises onto real instruction starts") {
    std::vector<uint64_t> starts;
    const Bytes b = make_stream(40, starts);
    auto doc = doc_of(b);
    for (size_t k : {size_t(30), size_t(77), size_t(200), size_t(301), size_t(439)}) {
        for (size_t n : {size_t(1), size_t(3), size_t(10), size_t(25)}) {
            CAPTURE(k);
            CAPTURE(n);
            CHECK(disasm_sync_back(*doc, starts[k], n, {}) == starts[k - n]);
        }
    }
    bool landed = false;
    CHECK(disasm_sync_back(*doc, starts[30], 3, {}, &landed) == starts[27]);
    CHECK(landed);
    // Inside a call's rel32 (E8 00 01 00 00): no decode chain lands there.
    const uint64_t mid = starts[4] + 2;
    const uint64_t fb = disasm_sync_back(*doc, mid, 3, {}, &landed);
    CHECK(fb <= mid);
    if (!landed) CHECK(fb == mid - 3);
    // Not enough history: the earliest start that still lands.
    CHECK(disasm_sync_back(*doc, starts[3], 10, {}) == 0);
    CHECK(disasm_sync_back(*doc, 0, 5, {}) == 0);
    CHECK(disasm_sync_back(*doc, starts[5], 0, {}) == starts[5]);
    // The result always lands exactly on the target when listed forward.
    for (uint64_t off = 1; off < 600; off += 37) {
        const uint64_t s = disasm_sync_back(*doc, off, 4, {});
        CHECK(s < off);
        std::vector<Insn> out;
        disasm_range(*doc, s, 64, no_address_map(*doc), {}, out);
        bool landed = false;
        for (const Insn& i : out) landed |= i.offset == off;
        CHECK(landed);
    }
}

TEST_CASE("disasm_sync_back: one row back uses more context than 15 bytes") {
    // Compiler output where the 15 bytes before the jmp also decode as a longer, wrong chain
    // ending in "and al, 0x38" (the tail of "mov [rsp+0x38], r12"): Up-arrow scrolling (n = 1)
    // used to land on that tail.
    const Bytes code = {
        0x48, 0xFF, 0x15, 0x9D, 0xE1, 0x02, 0x00,  // call qword ptr [rip+0x2E19D]
        0x0F, 0x1F, 0x44, 0x00, 0x00,              // nop dword ptr [rax+rax]
        0x85, 0xC0,                                // test eax, eax
        0x79, 0x16,                                // jns
        0x8B, 0xC8,                                // mov ecx, eax
        0xE8, 0xA5, 0x04, 0xFB, 0xFF,              // call rel32
        0x4C, 0x89, 0x64, 0x24, 0x38,              // mov qword ptr [rsp+0x38], r12
        0xE9, 0x94, 0x04, 0x00, 0x00,              // jmp rel32          <- offset 28
        0x48, 0x89, 0x4C, 0x24, 0x38,              // mov qword ptr [rsp+0x38], rcx
    };
    auto doc = doc_of(code);
    bool landed = false;
    CHECK(disasm_sync_back(*doc, 28, 1, {}, &landed) == 23);
    CHECK(landed);
    CHECK(disasm_sync_back(*doc, 28, 2, {}) == 18);
    CHECK(disasm_sync_back(*doc, 33, 1, {}) == 28);
}

// ---- address maps ----------------------------------------------------------------------------------

TEST_CASE("exe_map: PE32+ sections, round trips, entry point") {
    auto doc = doc_of(make_pe());
    AddressMap m;
    std::string err;
    REQUIRE(detect_pe(*doc, m, &err));
    CHECK(m.kind == AddressMap::Pe);
    CHECK(m.bits == 64);
    CHECK(m.base == 0x140000000ull);
    CHECK(m.format == "PE32+ x86-64");
    REQUIRE(m.regions.size() == 3);
    CHECK(m.regions[0].name == "(headers)");
    CHECK(m.regions[1].name == ".text");
    CHECK(m.regions[1].exec);
    CHECK_FALSE(m.regions[2].exec);

    uint64_t va = 0, off = 0;
    REQUIRE(m.offset_to_va(0x210, va));
    CHECK(va == 0x140001010ull);
    REQUIRE(m.offset_to_va(0x100, va));
    CHECK(va == 0x140000100ull);
    CHECK(m.section_at_offset(0x210) == ".text");
    CHECK(m.section_at_offset(0x450) == ".data");
    REQUIRE(m.entry_offset(off));
    CHECK(off == 0x210);
    CHECK(m.entry == 0x140001010ull);
    // .bss part of .data: inside the image, no file bytes.
    CHECK(m.contains_va(0x140002800ull));
    CHECK(m.section_at_va(0x140002800ull) == ".data");
    CHECK_FALSE(m.va_to_offset(0x140002800ull, off));
    CHECK_FALSE(m.contains_va(0x150000000ull));
    CHECK_FALSE(m.va_to_offset(0x13FFFFFFFull, off));
    CHECK(m.section_at_va(0x150000000ull).empty());
    // Every mapped offset round-trips.
    for (uint64_t o = 0; o < 0x600; o += 7) {
        REQUIRE(m.offset_to_va(o, va));
        REQUIRE(m.va_to_offset(va, off));
        CHECK(off == o);
    }
    CHECK_FALSE(m.offset_to_va(0x600, va));

    // detect_address_map picks PE; disasm_range uses its addresses.
    AddressMap a = detect_address_map(*doc, &err);
    CHECK(a.kind == AddressMap::Pe);
    CHECK(err.empty());
    std::vector<Insn> out;
    disasm_range(*doc, 0x210, 3, a, {}, out);
    REQUIRE(out.size() == 3);
    CHECK(out[0].address == 0x140001010ull);
    CHECK(out[0].target == 0x140001010ull + 7 + 0x2A);
    CHECK(out[1].text == "call 0x14000111c");  // 0x140001017 + 5 + 0x100
    CHECK(out[2].text == "ret");
}

TEST_CASE("exe_map: PE32 is a 32-bit image") {
    Bytes b = make_pe();
    put(b, 0x44, 0x14C, 2);
    put(b, 0x58, 0x10B, 2);
    put(b, 0x58 + 24, 0, 4);         // BaseOfData (PE32) - not the image base
    put(b, 0x58 + 28, 0x400000, 4);  // ImageBase
    auto doc = doc_of(b);
    AddressMap m;
    REQUIRE(detect_pe(*doc, m));
    CHECK(m.bits == 32);
    CHECK(m.base == 0x400000);
    CHECK(m.format == "PE32 x86");
    uint64_t va = 0;
    REQUIRE(m.offset_to_va(0x200, va));
    CHECK(va == 0x401000);
}

TEST_CASE("exe_map: ELF64 segments, section names, entry point") {
    auto doc = doc_of(make_elf());
    AddressMap m;
    std::string err;
    REQUIRE(detect_elf(*doc, m, &err));
    CHECK(m.kind == AddressMap::Elf);
    CHECK(m.bits == 64);
    CHECK(m.format == "ELF64 x86-64");
    REQUIRE(m.regions.size() == 2);
    CHECK(m.regions[1].exec);
    uint64_t va = 0, off = 0;
    REQUIRE(m.entry_offset(off));
    CHECK(off == 0x220);
    REQUIRE(m.offset_to_va(0x10, va));
    CHECK(va == 0x400010);
    CHECK(m.section_at_offset(0x220) == ".text");
    CHECK(m.section_at_offset(0x10) == "LOAD0");
    CHECK(m.section_at_va(0x402010) == ".bss");
    CHECK_FALSE(m.va_to_offset(0x402010, off));
    CHECK_FALSE(m.offset_to_va(0x350, va));  // section headers: not loaded
    for (uint64_t o = 0; o < 0x300; o += 5) {
        REQUIRE(m.offset_to_va(o, va));
        REQUIRE(m.va_to_offset(va, off));
        CHECK(off == o);
    }
    CHECK(detect_address_map(*doc).kind == AddressMap::Elf);

    // A TLS NOBITS section (.tbss) listed before .text at .text's address must not name it.
    Bytes t = make_elf();
    std::swap_ranges(t.begin() + 0x340, t.begin() + 0x380, t.begin() + 0x380);  // .bss first, then .text
    put(t, 0x340 + 8, 0x403, 8);       // SHF_ALLOC | SHF_WRITE | SHF_TLS
    put(t, 0x340 + 16, 0x401000, 8);   // sh_addr inside .text
    auto dt = doc_of(t);
    REQUIRE(detect_elf(*dt, m, &err));
    CHECK(m.section_at_va(0x401010) == ".text");
    CHECK(m.section_at_offset(0x220) == ".text");

    // ELF32 big endian (header + one PT_LOAD), names absent.
    Bytes e(0x100, 0);
    put_str(e, 0, "\x7F" "ELF");
    e[4] = 1;
    e[5] = 2;
    auto be16 = [&](size_t at, uint16_t v) { e[at] = uint8_t(v >> 8); e[at + 1] = uint8_t(v); };
    auto be32 = [&](size_t at, uint32_t v) { for (int i = 0; i < 4; ++i) e[at + size_t(i)] = uint8_t(v >> (24 - 8 * i)); };
    be16(18, 3);
    be32(24, 0x10000080);  // entry
    be32(28, 52);          // phoff
    be16(42, 32);
    be16(44, 1);
    be32(52, 1);           // PT_LOAD
    be32(52 + 4, 0);       // p_offset
    be32(52 + 8, 0x10000000);
    be32(52 + 16, 0x100);  // filesz
    be32(52 + 20, 0x100);
    be32(52 + 24, 5);
    auto d32 = doc_of(e);
    REQUIRE(detect_elf(*d32, m, &err));
    CHECK(m.bits == 32);
    CHECK(m.format == "ELF32 x86");
    REQUIRE(m.entry_offset(off));
    CHECK(off == 0x80);
}

TEST_CASE("exe_map: manual, none") {
    auto doc = doc_of(Bytes(0x100, 0x90));
    const AddressMap m = manual_address_map(*doc, 0x400000);
    uint64_t va = 0, off = 0;
    REQUIRE(m.offset_to_va(0x10, va));
    CHECK(va == 0x400010);
    REQUIRE(m.va_to_offset(0x4000FF, off));
    CHECK(off == 0xFF);
    CHECK_FALSE(m.va_to_offset(0x3FFFFF, off));
    CHECK_FALSE(m.va_to_offset(0x400101, off));
    CHECK(m.contains_va(0x400000));
    CHECK_FALSE(m.contains_va(0x400100));
    CHECK_FALSE(m.entry_offset(off));
    const AddressMap n = detect_address_map(*doc);
    CHECK(n.kind == AddressMap::None);
    REQUIRE(n.offset_to_va(0x20, va));
    CHECK(va == 0x20);
}

TEST_CASE("exe_map: malformed headers are rejected") {
    AddressMap m;
    std::string err;
    {  // truncated section table
        Bytes b = make_pe();
        b.resize(0x160);
        CHECK_FALSE(detect_pe(*doc_of(b), m, &err));
        CHECK(err.find("truncated") != std::string::npos);
    }
    {  // absurd section count
        Bytes b = make_pe();
        put(b, 0x46, 0xFFFF, 2);
        CHECK_FALSE(detect_pe(*doc_of(b), m, &err));
    }
    {  // e_lfanew far past EOF
        Bytes b = make_pe();
        put(b, 0x3C, 0xFFFFFFF0u, 4);
        CHECK_FALSE(detect_pe(*doc_of(b), m, &err));
    }
    {  // overlapping raw data
        Bytes b = make_pe();
        put(b, 0x58 + 0xF0 + 60, 0x300, 4);
        CHECK_FALSE(detect_pe(*doc_of(b), m, &err));
        CHECK(err.find("overlap") != std::string::npos);
        // detect_address_map falls back to None and says why.
        auto d = doc_of(b);
        CHECK(detect_address_map(*d, &err).kind == AddressMap::None);
        CHECK(err.find("overlap") != std::string::npos);
    }
    {  // overlapping virtual addresses
        Bytes b = make_pe();
        put(b, 0x58 + 0xF0 + 52, 0x1100, 4);
        CHECK_FALSE(detect_pe(*doc_of(b), m, &err));
    }
    {  // optional header magic garbage
        Bytes b = make_pe();
        put(b, 0x58, 0x1234, 2);
        CHECK_FALSE(detect_pe(*doc_of(b), m, &err));
    }
    {  // ELF: huge program header count, header table past EOF, overlap, truncated header
        Bytes b = make_elf();
        put(b, 56, 0xFFFF, 2);
        CHECK_FALSE(detect_elf(*doc_of(b), m, &err));
        b = make_elf();
        put(b, 32, 0xFFFFFFFFFFFFFF00ull, 8);
        CHECK_FALSE(detect_elf(*doc_of(b), m, &err));
        b = make_elf();
        put(b, 64 + 56 + 8, 0x100, 8);  // second segment starts inside the first
        CHECK_FALSE(detect_elf(*doc_of(b), m, &err));
        b = make_elf();
        put(b, 64 + 56 + 16, 0xFFFFFFFFFFFFFFF0ull, 8);  // address overflows
        CHECK_FALSE(detect_elf(*doc_of(b), m, &err));
        b = make_elf();
        b.resize(40);
        CHECK_FALSE(detect_elf(*doc_of(b), m, &err));
        b = make_elf();
        put(b, 40, 0xFFFFFFFFull, 8);   // bad section headers only lose the names
        REQUIRE(detect_elf(*doc_of(b), m, &err));
        CHECK(m.names.empty());
    }
    CHECK_FALSE(detect_pe(*doc_of({}), m, &err));
    CHECK_FALSE(detect_elf(*doc_of({'M', 'Z'}), m, &err));
}

TEST_CASE("exe_map: random header corruption never maps out of range") {
    std::mt19937 rng(1234);
    const Bytes bases[] = {make_pe(), make_elf()};
    for (int iter = 0; iter < 3000; ++iter) {
        Bytes b = bases[iter & 1];
        const int flips = 1 + int(rng() % 8);
        for (int f = 0; f < flips; ++f) b[rng() % 0x180] = uint8_t(rng());
        if (rng() % 4 == 0) b.resize(rng() % b.size());
        auto doc = doc_of(b);
        const AddressMap m = detect_address_map(*doc);
        for (const MappedRegion& r : m.regions) {
            if (r.file_size) CHECK(r.offset + r.file_size <= b.size());
            CHECK(r.file_size <= r.mem_size);
        }
        uint64_t va = 0, off = 0;
        for (uint64_t o = 0; o < b.size(); o += 17)
            if (m.offset_to_va(o, va)) {
                REQUIRE(m.va_to_offset(va, off));
                CHECK(off == o);
            }
        if (m.entry_offset(off)) CHECK(off < b.size());
    }
}

// ---- Lua: hx.disasm / doc:disasm -----------------------------------------------------------------

namespace {
struct Host : ScriptHost {
    std::unique_ptr<Document> doc;
    Document* active_document() override { return doc.get(); }
    Document* find_document(uint64_t id) override { return doc && doc->id() == id ? doc.get() : nullptr; }
    Document* open_bytes(const std::string&, const uint8_t*, size_t) override { return nullptr; }
    void reveal(Document&, uint64_t, uint64_t) override {}
};
}  // namespace

TEST_CASE("lua: hx.disasm and doc:disasm") {
    Host host;
    host.doc = doc_of(make_pe());
    ScriptEngine eng(&host);
    eng.set_script_dirs({});
    eng.reload();
    std::string err;
    CHECK(eng.run_source(R"(
        local r = hx.disasm("\x48\x8B\x05\x2A\x00\x00\x00\xE8\x00\x01\x00\x00\xC3\x06", 0x1000)
        assert(#r == 4, #r)
        assert(r[1].text == "mov rax, qword ptr [rip+0x2a]  ; 0x1031", r[1].text)
        assert(r[1].address == 0x1000 and r[1].offset == 0 and r[1].length == 7 and r[1].target == 0x1031)
        assert(r[1].bytes == "\x48\x8B\x05\x2A\x00\x00\x00" and r[1].valid and r[1].flow == nil)
        assert(r[2].flow == "call" and r[2].target == 0x1007 + 5 + 0x100 and r[2].offset == 7)
        assert(r[3].text == "ret" and r[3].flow == "ret")
        assert(r[4].text == "db 0x06" and not r[4].valid)
        local x = hx.disasm("\x06", 0, 32)
        assert(x[1].text == "push es")
        assert(hx.disasm("\x06", 0, "x86")[1].valid)
        assert(#hx.disasm("") == 0)
        assert(not pcall(hx.disasm, "\x90", 0, 16))

        local d = hx.doc()
        local l = d:disasm(0x210, 3)
        assert(#l == 3)
        assert(l[1].address == 0x140001010 and l[1].offset == 0x210 and l[1].section == ".text")
        assert(l[2].text == "call 0x14000111c", l[2].text)
        assert(#d:disasm(0x210) == 16)
        assert(#d:disasm(0x5FF, 10) == 1)
        assert(#d:disasm(0x600, 10) == 0)
        assert(d:disasm(0x210, 1, 32)[1].text ~= l[1].text)
        assert(not pcall(d.disasm, d, 0, 20000))
    )", "disasm_test", &err));
    CHECK(err.empty());
    if (!err.empty()) MESSAGE(err);
}

// ---- the Disassembly panel, headless (an ImGui context without a window, as in test_ui.cpp) -------

namespace {
struct PanelUi {
    ImGuiContext* ctx = nullptr;
    std::unique_ptr<Document> doc;
    DisasmPanel panel;
    DisasmPanelCallbacks cb;
    int selects = 0, jumps = 0;
    uint64_t sel_off = 0, sel_len = 0, jump_off = 0;
    float w = 900.0f, h = 600.0f;

    explicit PanelUi(const Bytes& data) : PanelUi(Document::create_from_bytes("code", data.data(), data.size())) {}
    // `restore`: Follow cursor off + the document's "disasm.*" extras before the first draw.
    explicit PanelUi(std::unique_ptr<Document> d, bool restore = false) {
        ctx = ImGui::CreateContext();
        ImGuiIO& io = ImGui::GetIO();
        io.IniFilename = nullptr;
        io.LogFilename = nullptr;
        io.BackendFlags |= ImGuiBackendFlags_RendererHasTextures;
        io.Fonts->AddFontDefault();
        doc = std::move(d);
        if (restore) {
            panel.follow = false;
            panel.restore_extras(*doc);
        }
        // The host's callbacks, like the app's: select moves the caret / selection, jump too.
        cb.select = [this](uint64_t off, uint64_t len) {
            ++selects;
            sel_off = off;
            sel_len = len;
            doc->view().cursor = off;
            doc->view().anchor = off + len;
        };
        cb.jump = [this](uint64_t off) {
            ++jumps;
            jump_off = off;
            doc->view().cursor = doc->view().anchor = off;
        };
        frame();
        frame();
    }
    ~PanelUi() { ImGui::DestroyContext(ctx); }
    void frame(float dt = 1.0f / 60.0f) {
        ImGuiIO& io = ImGui::GetIO();
        io.DisplaySize = ImVec2(w, h);
        io.DeltaTime = dt;
        ImGui::NewFrame();
        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(ImVec2(w, h));
        ImGui::Begin("host", nullptr, ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings);
        panel.draw(doc.get(), doc->view().sel_begin(), cb);
        ImGui::End();
        ImGui::Render();
    }
    std::vector<Insn> rows() const { return panel.listing(doc->id()); }
    ImVec2 row(int r) const {
        float x = 0, y = 0;
        REQUIRE(panel.row_pos(r, x, y));
        return ImVec2(x, y);
    }
    void move(ImVec2 p) {
        ImGui::GetIO().AddMousePosEvent(p.x, p.y);
        frame();
    }
    void button(bool down) {
        ImGui::GetIO().AddMouseButtonEvent(0, down);
        frame();
    }
    void settle() { frame(1.0f); }  // long gap: the next click is never part of a double-click
    void click(ImVec2 p) {
        move(p);
        button(true);
        button(false);
        settle();
    }
    void double_click(ImVec2 p) {
        move(p);
        button(true);
        button(false);
        button(true);
        button(false);
        settle();
    }
    void wheel(float dy) {
        ImGui::GetIO().AddMouseWheelEvent(0.0f, dy);
        frame();
        frame();
    }
    void caret(uint64_t off) {
        doc->view().cursor = doc->view().anchor = off;
        frame();
        frame();
    }
    void key(ImGuiKey k) {
        ImGui::GetIO().AddKeyEvent(k, true);
        frame();
        ImGui::GetIO().AddKeyEvent(k, false);
        frame();
    }
    void type(const char* s) {
        ImGui::GetIO().AddInputCharactersUTF8(s);
        frame();
    }
    std::vector<std::string> lines() const { return panel.listing_lines(doc->id()); }
};
}  // namespace

TEST_CASE("disasm panel: follows the caret, scrolls, clicks select, double-click follows") {
    std::vector<uint64_t> starts;
    const Bytes code = make_stream(200, starts);
    PanelUi ui(code);
    ui.panel.mode = 1;  // 64-bit (no header: Auto would be 64 too)

    // Follow: the caret's instruction is listed (a few rows below the top) and is the current one.
    ui.caret(starts[500]);
    std::vector<Insn> r = ui.rows();
    REQUIRE(r.size() > 10);
    CHECK(r.front().offset < starts[500]);
    size_t at = 0;
    while (at < r.size() && r[at].offset != starts[500]) ++at;
    REQUIRE(at < r.size());
    CHECK(at <= 8);
    for (size_t k = 0; k < r.size(); ++k) CHECK(r[k].offset == starts[500 - at + k]);
    const HighlightSet* layer = ui.panel.layer(ui.doc->id());
    REQUIRE(layer);
    REQUIRE(layer->items.size() == 1);
    CHECK(layer->items[0].offset == starts[500]);

    // A caret move inside the listing keeps it; one outside re-anchors.
    const uint64_t top = r.front().offset;
    ui.caret(starts[500 + 3]);
    CHECK(ui.rows().front().offset == top);
    ui.caret(starts[1500]);
    CHECK(ui.rows().front().offset != top);
    CHECK(ui.rows().front().offset < starts[1500]);

    // Follow off: the listing stays.
    ui.panel.follow = false;
    const uint64_t top2 = ui.rows().front().offset;
    ui.caret(starts[100]);
    CHECK(ui.rows().front().offset == top2);
    ui.panel.follow = true;

    // Wheel: 3 instructions per notch, down then back up (backwards via disasm_sync_back).
    ui.caret(starts[1000]);
    const uint64_t t0 = ui.rows().front().offset;
    size_t k0 = 0;
    while (starts[k0] != t0) ++k0;
    ui.move(ui.row(5));
    ui.wheel(-1.0f);
    CHECK(ui.rows().front().offset == starts[k0 + 3]);
    ui.wheel(1.0f);
    CHECK(ui.rows().front().offset == t0);

    // Click a row: its bytes are selected (no jump), the listing stays.
    r = ui.rows();
    ui.click(ui.row(2));
    CHECK(ui.selects >= 1);
    CHECK(ui.sel_off == r[2].offset);
    CHECK(ui.sel_len == r[2].length);
    CHECK(ui.rows().front().offset == t0);
    CHECK(ui.jumps == 0);

    // Double-click a call: follow its target (a jump), which gets listed.
    r = ui.rows();
    int call = -1;
    for (int k = 0; k < int(r.size()); ++k)
        if (r[size_t(k)].flow == Insn::Call) {
            call = k;
            break;
        }
    REQUIRE(call >= 0);
    const uint64_t target = r[size_t(call)].target;  // address == offset (no address map)
    ui.double_click(ui.row(call));
    CHECK(ui.jumps == 1);
    CHECK(ui.jump_off == target);
    bool listed = false;
    for (const Insn& i : ui.rows()) listed |= i.offset == target;
    CHECK(listed);


    // Pinned start: Follow off, listing from exactly there.
    ui.panel.show_at(*ui.doc, starts[42], true);
    ui.frame();
    CHECK_FALSE(ui.panel.follow);
    CHECK(ui.rows().front().offset == starts[42]);

    // follow_at on a call instruction (or a byte inside the listed one) jumps to its target.
    const int jumps = ui.jumps;
    size_t c = 0;
    while (code[size_t(starts[c])] != 0xE8) ++c;
    CHECK(ui.panel.follow_at(*ui.doc, starts[c], ui.cb));
    CHECK(ui.jumps == jumps + 1);
    ui.panel.show_at(*ui.doc, starts[c], true);
    ui.frame();
    CHECK(ui.panel.follow_at(*ui.doc, starts[c] + 2, ui.cb));
    CHECK(ui.jumps == jumps + 2);
    CHECK_FALSE(ui.panel.follow_at(*ui.doc, starts[0], ui.cb));  // push rbp: no target
}

TEST_CASE("disasm panel: entry point and address map") {
    PanelUi ui(make_pe());
    uint64_t off = 0;
    REQUIRE(ui.panel.entry_offset(*ui.doc, off));
    CHECK(off == 0x210);
    CHECK(ui.panel.address_map(*ui.doc).kind == AddressMap::Pe);
    ui.panel.show_at(*ui.doc, off, false);
    ui.frame();
    const std::vector<Insn> r = ui.rows();
    REQUIRE(!r.empty());
    CHECK(r[0].offset == 0x210);
    CHECK(r[0].address == 0x140001010ull);
    CHECK(ui.panel.options_for(*ui.doc).mode == DisasmMode::X64);
}

TEST_CASE("disasm panel: empty document") {
    PanelUi ui(Bytes{});
    CHECK(ui.rows().empty());
    CHECK(ui.panel.layer(ui.doc->id()) == nullptr);
}

// ---- symbols in the Disassembly panel (core/symbols.h) ----------------------------------------------

TEST_CASE("disasm panel: symbol labels, IAT / branch annotations, clicks under label rows") {
    PanelUi ui(symfix::make_pe());
    const SymbolTable* syms = ui.panel.symbols(*ui.doc, true);
    REQUIRE(syms);
    CHECK(syms->symbols.size() == 5);
    uint64_t off = 0;
    REQUIRE(ui.panel.entry_offset(*ui.doc, off));
    CHECK(off == 0x200);
    ui.panel.show_at(*ui.doc, off, true);
    ui.frame();
    const std::vector<std::string> l = ui.lines();
    REQUIRE(l.size() >= 12);
    CHECK(l[0] == "test.dll!Alpha:");
    CHECK(l[1] == "call qword ptr [rip+0x12fa]  ; KERNEL32.dll!GetProcAddress");
    CHECK(l[2] == "ret");
    CHECK(l[3] == "nop");
    CHECK(l[8] == "test.dll!#6:");
    CHECK(l[9] == "jmp 0x140001000  ; test.dll!Alpha");
    CHECK(l[10] == "jnz 0x140001006  ; test.dll!Alpha+0x6");  // nearest symbol + offset
    // Label rows take a row each: listed instruction 0 is drawn below "test.dll!Alpha:".
    const std::vector<Insn> r = ui.rows();
    REQUIRE(r.size() >= 8);
    CHECK(r[0].offset == 0x200);
    ui.click(ui.row(0));
    CHECK(ui.sel_off == 0x200);
    CHECK(ui.sel_len == 6);
    ui.click(ui.row(7));  // the jmp (below the second label)
    CHECK(ui.sel_off == 0x210);
    CHECK(ui.sel_len == 2);
    CHECK(ui.jumps == 0);
    // Following the call's IAT slot (data in .rdata) still works.
    CHECK(ui.panel.follow_at(*ui.doc, 0x200, ui.cb));
    CHECK(ui.jump_off == 0x700);

    // 32-bit: call dword ptr [abs] through the IAT.
    PanelUi u32(symfix::make_pe(false));
    REQUIRE(u32.panel.symbols(*u32.doc, true));
    u32.panel.show_at(*u32.doc, 0x200, true);
    u32.frame();
    REQUIRE(u32.lines().size() > 2);
    CHECK(u32.lines()[1] == "call dword ptr [0x402300]  ; KERNEL32.dll!GetProcAddress");
}

TEST_CASE("disasm panel: PageDown / PageUp skip no instruction when label rows take space") {
    // Two labels (Alpha @ 0x200, #6 @ 0x210) on the first page: it lists two instructions fewer
    // than it has rows, so paging by the row count would jump over instructions never shown.
    PanelUi ui(symfix::make_pe());
    REQUIRE(ui.panel.symbols(*ui.doc, true));
    ui.panel.show_at(*ui.doc, 0x200, true);
    ui.frame();
    const std::vector<Insn> p1 = ui.rows();
    REQUIRE(p1.size() > 10);
    REQUIRE(ui.lines()[0] == "test.dll!Alpha:");
    ui.key(ImGuiKey_PageDown);
    const std::vector<Insn> p2 = ui.rows();
    REQUIRE(!p2.empty());
    CHECK(p2.front().offset > p1.front().offset);
    CHECK(p2.front().offset <= p1.back().offset);  // overlaps the previous page: nothing skipped
    ui.key(ImGuiKey_PageUp);
    const std::vector<Insn> p3 = ui.rows();
    REQUIRE(!p3.empty());
    CHECK(p3.front().offset < p2.front().offset);
    CHECK(p3.back().offset + p3.back().length >= p2.front().offset);  // reaches the old top

    // PageUp onto a page that holds both labels (nops around the code so that decoding backwards
    // is unambiguous): that page also ends at the old top instead of one instruction before it.
    Bytes b = symfix::make_pe();
    for (size_t i = 0x1C0; i < 0x200; ++i) b[i] = 0x90;
    for (size_t i = 0x208; i < 0x210; ++i) b[i] = 0x90;
    for (size_t i = 0x214; i < 0x400; ++i) b[i] = 0x90;
    PanelUi nu(b);
    REQUIRE(nu.panel.symbols(*nu.doc, true));
    nu.panel.show_at(*nu.doc, 0x200, true);
    nu.frame();
    const std::vector<Insn> q1 = nu.rows();
    REQUIRE(q1.size() > 10);
    nu.panel.show_at(*nu.doc, q1.back().offset, true);
    nu.frame();
    const uint64_t top = nu.rows().front().offset;
    nu.key(ImGuiKey_PageUp);
    const std::vector<Insn> q2 = nu.rows();
    REQUIRE(!q2.empty());
    CHECK(q2.front().offset < top);
    CHECK(q2.back().offset + q2.back().length >= top);
    CHECK(q2.front().offset == 0x200);
}

TEST_CASE("disasm panel: ELF function labels, @plt / @got annotations") {
    PanelUi ui(symfix::make_elf());
    REQUIRE(ui.panel.symbols(*ui.doc, true));
    ui.panel.show_at(*ui.doc, 0x200, true);
    ui.frame();
    const std::vector<std::string> l = ui.lines();
    REQUIRE(l.size() >= 4);
    CHECK(l[0] == "main:");
    CHECK(l[1] == "call 0x400300  ; puts@plt");
    CHECK(l[2] == "mov rax, qword ptr [rip+0x204]  ; puts@got");
    CHECK(l[3] == "ret");
    // The PLT stub itself is labelled.
    ui.panel.show_at(*ui.doc, 0x300, true);
    ui.frame();
    REQUIRE(!ui.lines().empty());
    CHECK(ui.lines()[0] == "puts@plt:");
}

TEST_CASE("disasm panel: Go to Symbol list filters and jumps") {
    PanelUi ui(symfix::make_pe());
    REQUIRE(ui.panel.symbols(*ui.doc, true));
    ui.panel.open_symbol_list();
    ui.frame();
    ui.frame();
    REQUIRE(ui.panel.symbol_list_open());
    ui.type("TEST.dll");  // case-insensitive: Alpha, #6
    ui.key(ImGuiKey_DownArrow);
    ui.key(ImGuiKey_Enter);
    CHECK_FALSE(ui.panel.symbol_list_open());
    CHECK(ui.jumps == 1);
    CHECK(ui.jump_off == 0x210);
    REQUIRE(!ui.rows().empty());
    CHECK(ui.rows().front().offset == 0x210);
    CHECK(ui.lines()[0] == "test.dll!#6:");

    ui.panel.open_symbol_list();
    ui.frame();
    ui.frame();
    ui.type("messagebox");
    ui.key(ImGuiKey_Enter);
    CHECK(ui.jumps == 2);
    CHECK(ui.jump_off == 0x740);  // the delay-load IAT slot

    ui.panel.open_symbol_list();  // Escape closes without a jump
    ui.frame();
    ui.frame();
    ui.key(ImGuiKey_Escape);
    CHECK_FALSE(ui.panel.symbol_list_open());
    CHECK(ui.jumps == 2);
}

TEST_CASE("disasm panel: symbols are rebuilt after an edit of the header tables") {
    PanelUi ui(symfix::make_pe());
    REQUIRE(ui.panel.symbols(*ui.doc, true));
    CHECK(ui.panel.symbols(*ui.doc)->at(0x140001000ull)->name == "Alpha");
    const uint8_t b = 'O';  // "Alpha" -> "Olpha" (.rdata RVA 0x2110 = file 0x510)
    REQUIRE(ui.doc->overwrite(0x510, &b, 1));
    const SymbolTable* t = ui.panel.symbols(*ui.doc, true);
    REQUIRE(t);
    CHECK(t->at(0x140001000ull)->name == "Olpha");
}

namespace {
struct TmpDir {
    std::filesystem::path dir;
    TmpDir() {
        std::random_device rd;
        dir = std::filesystem::temp_directory_path() / ("hexer-test-disasm-" + std::to_string(rd()) + std::to_string(rd()));
        std::filesystem::create_directories(dir);
    }
    ~TmpDir() {
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }
};
}  // namespace

TEST_CASE("disasm panel: map choice, manual base and pinned start survive a session round trip") {
    TmpDir tmp;
    const Bytes pe = symfix::make_pe();
    {
        auto doc = Document::create_from_bytes("code", pe.data(), pe.size());
        DisasmPanel p;
        p.save_extras(*doc);  // defaults: nothing stored
        CHECK(doc->extras().empty());
        p.set_map_choice(*doc, DisasmMapChoice::Manual, 0x8000);
        p.show_at(*doc, 0x210, true);  // pins: Follow cursor off
        p.save_extras(*doc);
        CHECK(doc->extra("disasm.map") == "manual");
        CHECK(doc->extra("disasm.base") == "8000");
        CHECK(doc->extra("disasm.top") == "528");
        Session s(tmp.dir.string());
        REQUIRE(s.save({doc.get()}, 0));
    }
    Session s(tmp.dir.string());
    auto r = s.load();
    REQUIRE(r.docs.size() == 1);
    PanelUi ui(std::move(r.docs[0]), true);
    CHECK(ui.panel.address_map(*ui.doc).kind == AddressMap::Manual);
    CHECK(ui.panel.address_map(*ui.doc).base == 0x8000);
    REQUIRE(!ui.rows().empty());
    CHECK(ui.rows().front().offset == 0x210);
    CHECK(ui.rows().front().address == 0x8210);

    // Following the caret again: no pinned start is stored; Auto erases the map keys.
    ui.panel.follow = true;
    ui.panel.set_map_choice(*ui.doc, DisasmMapChoice::Auto);
    ui.panel.save_extras(*ui.doc);
    CHECK(ui.doc->extras().empty());
    ui.panel.set_map_choice(*ui.doc, DisasmMapChoice::None);
    ui.panel.save_extras(*ui.doc);
    CHECK(ui.doc->extra("disasm.map") == "none");
}

TEST_CASE("lua: doc:symbols") {
    Host host;
    host.doc = doc_of(symfix::make_pe());
    ScriptEngine eng(&host);
    eng.set_script_dirs({});
    eng.reload();
    std::string err;
    CHECK(eng.run_source(R"(
        local s = hx.doc():symbols()
        assert(#s == 6, #s)
        local by = {}
        for _, x in ipairs(s) do by[(x.module ~= "" and x.module .. "!" or "") .. x.name] = x end
        local a = by["test.dll!Alpha"]
        assert(a.kind == "export" and a.address == 0x140001000 and a.offset == 0x200 and a.ordinal == 5)
        local g = by["KERNEL32.dll!GetProcAddress"]
        assert(g.kind == "import" and g.address == 0x140002300 and g.offset == 0x700 and g.ordinal == nil)
        assert(by["KERNEL32.dll!#16"].ordinal == 16)
        assert(by["USER32.dll!MessageBoxW"].address == 0x140002340)
        local f = s[#s]
        assert(f.name == "Fwd" and f.forward == "NTDLL.RtlFoo" and f.address == nil and f.offset == nil)
        assert(f.kind == "export" and f.module == "test.dll" and f.ordinal == 8)
        for i = 2, #s - 1 do assert(s[i - 1].address <= s[i].address) end
    )", "symbols_pe", &err));
    CHECK(err.empty());
    if (!err.empty()) MESSAGE(err);

    host.doc = doc_of(symfix::make_elf());
    CHECK(eng.run_source(R"(
        local s = hx.doc():symbols()
        assert(#s == 7, #s)
        assert(s[1].name == "main" and s[1].kind == "function" and s[1].module == "" and s[1].offset == 0x200)
        local plt = 0
        for _, x in ipairs(s) do if x.name:find("@plt$") then plt = plt + 1 end end
        assert(plt == 2)
    )", "symbols_elf", &err));
    CHECK(err.empty());
    if (!err.empty()) MESSAGE(err);

    host.doc = doc_of(Bytes(64, 0x90));
    CHECK(eng.run_source("assert(#hx.doc():symbols() == 0)", "symbols_none", &err));
    CHECK(err.empty());
}
