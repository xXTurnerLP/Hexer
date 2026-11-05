#pragma once
// Small executables with symbol tables for test_symbols / test_disasm (core/symbols.h).
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <string>
#include <vector>

namespace symfix {

using Bytes = std::vector<uint8_t>;

inline void put(Bytes& b, size_t off, uint64_t v, int n) {
    if (b.size() < off + size_t(n)) b.resize(off + size_t(n));
    for (int i = 0; i < n; ++i) b[off + size_t(i)] = uint8_t(v >> (8 * i));
}

inline void put_str(Bytes& b, size_t off, const char* s) {  // with the NUL
    const size_t n = std::strlen(s) + 1;
    if (b.size() < off + n) b.resize(off + n);
    std::memcpy(b.data() + off, s, n);
}

// PE32+ (or PE32 with plus = false), image base 0x140000000 (PE32: 0x400000):
//   headers [0, 0x200); .text raw [0x200, 0x400) RVA 0x1000; .rdata raw [0x400, 0x800) RVA 0x2000.
//   Exports (dir RVA 0x2000, size 0x140, "test.dll", ordinal base 5): Alpha = ord 5 @ RVA 0x1000,
//     ord 6 unnamed @ RVA 0x1010, ord 7 unused, Fwd = ord 8 forwarded to "NTDLL.RtlFoo".
//   Imports (dir RVA 0x2200): KERNEL32.dll GetProcAddress (IAT RVA 0x2300) and #16 (next slot).
//   Delay imports (dir RVA 0x2380): USER32.dll MessageBoxW (IAT RVA 0x2340).
//   Code at RVA 0x1000 (file 0x200): call [rip -> IAT GetProcAddress] (PE32: call [abs]); ret; nop;
//   at RVA 0x1010 (file 0x210): jmp 0x..1000 (Alpha); jnz 0x..1006 (Alpha+6).
//   Entry point RVA 0x1000.
inline Bytes make_pe(bool plus = true) {
    Bytes b(0x800, 0);
    const uint64_t base = plus ? 0x140000000ull : 0x400000ull;
    put_str(b, 0, "MZ");
    put(b, 0x3C, 0x40, 4);
    put(b, 0x40, 0x4550, 4);                // "PE\0\0"
    put(b, 0x44, plus ? 0x8664 : 0x14C, 2);
    put(b, 0x46, 2, 2);                     // sections
    const uint64_t opt_size = plus ? 0xF0 : 0xE0;
    put(b, 0x54, opt_size, 2);
    const size_t opt = 0x58;
    put(b, opt, plus ? 0x20B : 0x10B, 2);
    put(b, opt + 16, 0x1000, 4);            // entry
    if (plus) put(b, opt + 24, base, 8);
    else put(b, opt + 28, base, 4);
    put(b, opt + 32, 0x1000, 4);            // SectionAlignment
    put(b, opt + 36, 0x200, 4);
    put(b, opt + 56, 0x3000, 4);
    put(b, opt + 60, 0x200, 4);             // SizeOfHeaders
    const size_t dirs = opt + (plus ? 112 : 96);
    put(b, dirs - 4, 16, 4);                // NumberOfRvaAndSizes
    put(b, dirs + 0 * 8, 0x2000, 4);        // export
    put(b, dirs + 0 * 8 + 4, 0x140, 4);
    put(b, dirs + 1 * 8, 0x2200, 4);        // import
    put(b, dirs + 1 * 8 + 4, 40, 4);
    put(b, dirs + 13 * 8, 0x2380, 4);       // delay import
    put(b, dirs + 13 * 8 + 4, 64, 4);
    const size_t sec = opt + size_t(opt_size);
    std::memcpy(b.data() + sec, ".text", 5);
    put(b, sec + 8, 0x200, 4);
    put(b, sec + 12, 0x1000, 4);
    put(b, sec + 16, 0x200, 4);
    put(b, sec + 20, 0x200, 4);
    put(b, sec + 36, 0x60000020, 4);
    std::memcpy(b.data() + sec + 40, ".rdata", 6);
    put(b, sec + 48, 0x400, 4);
    put(b, sec + 52, 0x2000, 4);
    put(b, sec + 56, 0x400, 4);
    put(b, sec + 60, 0x400, 4);
    put(b, sec + 76, 0x40000040, 4);
    auto at = [](uint64_t rva) { return size_t(rva - 0x2000 + 0x400); };  // .rdata RVA -> file
    // Export directory.
    const size_t ed = at(0x2000);
    put(b, ed + 12, 0x2100, 4);   // Name
    put(b, ed + 16, 5, 4);        // OrdinalBase
    put(b, ed + 20, 4, 4);        // NumberOfFunctions
    put(b, ed + 24, 2, 4);        // NumberOfNames
    put(b, ed + 28, 0x2040, 4);
    put(b, ed + 32, 0x2060, 4);
    put(b, ed + 36, 0x2070, 4);
    put(b, at(0x2040), 0x1000, 4);
    put(b, at(0x2044), 0x1010, 4);
    put(b, at(0x2048), 0, 4);
    put(b, at(0x204C), 0x2120, 4);  // inside the export directory: a forwarder
    put(b, at(0x2060), 0x2110, 4);
    put(b, at(0x2064), 0x2118, 4);
    put(b, at(0x2070), 0, 2);
    put(b, at(0x2072), 3, 2);
    put_str(b, at(0x2100), "test.dll");
    put_str(b, at(0x2110), "Alpha");
    put_str(b, at(0x2118), "Fwd");
    put_str(b, at(0x2120), "NTDLL.RtlFoo");
    // Import directory: one descriptor + the terminator.
    const int ts = plus ? 8 : 4;
    put(b, at(0x2200), 0x2260, 4);       // OriginalFirstThunk
    put(b, at(0x2200) + 12, 0x2280, 4);  // Name
    put(b, at(0x2200) + 16, 0x2300, 4);  // FirstThunk
    const uint64_t by_ord = plus ? (1ull << 63) | 16 : (1ull << 31) | 16;
    for (uint64_t t : {uint64_t(0x2260), uint64_t(0x2300)}) {
        put(b, at(t), 0x22A0, ts);
        put(b, at(t) + size_t(ts), by_ord, ts);
    }
    put_str(b, at(0x2280), "KERNEL32.dll");
    put_str(b, at(0x22A2), "GetProcAddress");
    // Delay-load directory.
    put(b, at(0x2380), 1, 4);            // RVA based
    put(b, at(0x2380) + 4, 0x23C0, 4);   // DllName
    put(b, at(0x2380) + 8, 0x23F0, 4);   // ModuleHandle
    put(b, at(0x2380) + 12, 0x2340, 4);  // IAT
    put(b, at(0x2380) + 16, 0x2350, 4);  // INT
    put(b, at(0x2340), base + 0x1100, ts);
    put(b, at(0x2350), 0x23D0, ts);
    put_str(b, at(0x23C0), "USER32.dll");
    put_str(b, at(0x23D2), "MessageBoxW");
    // Code: call [IAT GetProcAddress]; ret.
    b[0x200] = 0xFF;
    b[0x201] = 0x15;
    put(b, 0x202, plus ? 0x2300 - 0x1006 : base + 0x2300, 4);
    b[0x206] = 0xC3;
    b[0x207] = 0x90;  // nop: the zero bytes after it decode as 2-byte instructions up to 0x210
    // RVA 0x1010 (export #6): jmp Alpha; jnz Alpha+6
    b[0x210] = 0xEB;
    b[0x211] = 0xEE;
    b[0x212] = 0x75;
    b[0x213] = 0xF2;
    return b;
}

// ELF64 x86-64 ET_DYN, one PT_LOAD [0, 0x1100) at 0x400000:
//   .text 0x400200 (main @ 0x400200: call puts@plt; mov rax, [rip -> puts@got]; ret; helper @ 0x400240),
//   .plt.sec 0x400300 (two IBT stubs: endbr64; bnd jmp [rip -> GOT slot]), .got 0x400400
//   (counter object @ 0x400408, puts slot 0x400410, malloc slot 0x400418), .dynsym (puts, malloc
//   UNDEF, main again), .rela.plt (two JUMP_SLOTs), .symtab (main, counter, helper, UNDEF puts, a
//   FILE symbol).
inline Bytes make_elf() {
    Bytes b(0x1100, 0);
    std::memcpy(b.data(), "\x7F" "ELF", 4);
    b[4] = 2;
    b[5] = 1;
    b[6] = 1;
    put(b, 16, 3, 2);         // ET_DYN
    put(b, 18, 62, 2);
    put(b, 20, 1, 4);
    put(b, 24, 0x400200, 8);  // entry
    put(b, 32, 64, 8);        // phoff
    put(b, 40, 0xE00, 8);     // shoff
    put(b, 52, 64, 2);
    put(b, 54, 56, 2);
    put(b, 56, 1, 2);
    put(b, 58, 64, 2);
    put(b, 60, 10, 2);        // shnum
    put(b, 62, 9, 2);         // shstrndx
    put(b, 64, 1, 4);         // PT_LOAD
    put(b, 68, 7, 4);
    put(b, 72, 0, 8);
    put(b, 80, 0x400000, 8);
    put(b, 88, 0x400000, 8);
    put(b, 96, 0x1100, 8);
    put(b, 104, 0x1100, 8);
    std::string shstr(1, '\0');
    auto name = [&](const char* n) {
        const size_t at = shstr.size();
        shstr += n;
        shstr += '\0';
        return uint64_t(at);
    };
    auto sh = [&](size_t i, const char* n, uint32_t type, uint64_t flags, uint64_t addr, uint64_t off, uint64_t size,
                  uint32_t link, uint32_t info, uint64_t entsize) {
        const size_t at = 0xE00 + i * 64;
        put(b, at, name(n), 4);
        put(b, at + 4, type, 4);
        put(b, at + 8, flags, 8);
        put(b, at + 16, addr, 8);
        put(b, at + 24, off, 8);
        put(b, at + 32, size, 8);
        put(b, at + 40, link, 4);
        put(b, at + 44, info, 4);
        put(b, at + 56, entsize, 8);
    };
    auto sym = [&](size_t at, uint32_t nm, uint8_t info, uint16_t shndx, uint64_t value) {
        put(b, at, nm, 4);
        b[at + 4] = info;
        put(b, at + 6, shndx, 2);
        put(b, at + 8, value, 8);
    };
    sh(1, ".text", 1, 6, 0x400200, 0x200, 0x100, 0, 0, 0);
    sh(2, ".plt.sec", 1, 6, 0x400300, 0x300, 0x20, 0, 0, 16);
    sh(3, ".got", 1, 3, 0x400400, 0x400, 0x20, 0, 0, 8);
    sh(4, ".dynsym", 11, 2, 0x400500, 0x500, 4 * 24, 5, 1, 24);
    sh(5, ".dynstr", 3, 2, 0x400600, 0x600, 18, 0, 0, 0);
    sh(6, ".rela.plt", 4, 2, 0x400700, 0x700, 2 * 24, 4, 2, 24);
    sh(7, ".symtab", 2, 0, 0, 0x800, 6 * 24, 8, 1, 24);
    sh(8, ".strtab", 3, 0, 0, 0x900, 33, 0, 0, 0);
    // .dynsym: puts @1, malloc @6, main @13
    const char dynstr[] = "\0puts\0malloc\0main";
    std::memcpy(b.data() + 0x600, dynstr, sizeof dynstr);
    sym(0x500 + 24, 1, 0x12, 0, 0);
    sym(0x500 + 48, 6, 0x12, 0, 0);
    sym(0x500 + 72, 13, 0x12, 1, 0x400200);
    // .rela.plt
    put(b, 0x700, 0x400410, 8);
    put(b, 0x708, (1ull << 32) | 7, 8);
    put(b, 0x718, 0x400418, 8);
    put(b, 0x720, (2ull << 32) | 7, 8);
    // .symtab: main @1, counter @6, helper @14, puts @21, file.c @26
    const char strtab[] = "\0main\0counter\0helper\0puts\0file.c";
    std::memcpy(b.data() + 0x900, strtab, sizeof strtab);
    sym(0x800 + 24, 1, 0x12, 1, 0x400200);
    sym(0x800 + 48, 6, 0x11, 3, 0x400408);
    sym(0x800 + 72, 14, 0x02, 1, 0x400240);
    sym(0x800 + 96, 21, 0x12, 0, 0);
    sym(0x800 + 120, 26, 0x04, 0xFFF1, 1);
    // .plt.sec stubs: f3 0f 1e fa | f2 ff 25 disp32 | 0f 1f 44 00 00
    for (int i = 0; i < 2; ++i) {
        const size_t at = 0x300 + size_t(i) * 16;
        const uint8_t stub[] = {0xF3, 0x0F, 0x1E, 0xFA, 0xF2, 0xFF, 0x25, 0, 0, 0, 0, 0x0F, 0x1F, 0x44, 0x00, 0x00};
        std::memcpy(b.data() + at, stub, sizeof stub);
        const uint64_t end = 0x400000 + at + 11;
        put(b, at + 7, 0x400410 + uint64_t(i) * 8 - end, 4);
    }
    // main: call 0x400300; mov rax, [rip -> 0x400410]; ret
    b[0x200] = 0xE8;
    put(b, 0x201, 0x400300 - 0x400205, 4);
    b[0x205] = 0x48;
    b[0x206] = 0x8B;
    b[0x207] = 0x05;
    put(b, 0x208, 0x400410 - 0x40020C, 4);
    b[0x20C] = 0xC3;
    // .shstrtab last (names were collected by sh()).
    const uint64_t shstr_name = name(".shstrtab");
    const size_t at = 0xE00 + 9 * 64;
    put(b, at, shstr_name, 4);
    put(b, at + 4, 3, 4);
    put(b, at + 24, 0xA00, 8);
    put(b, at + 32, shstr.size(), 8);
    std::memcpy(b.data() + 0xA00, shstr.data(), shstr.size());
    return b;
}

}  // namespace symfix
