// Symbol tables of executables (core/symbols.h): PE exports / imports, ELF symtab / PLT names.
#include <doctest/doctest.h>

#include <atomic>
#include <cstdint>
#include <memory>
#include <random>
#include <string>
#include <vector>

#include "core/document.h"
#include "core/exe_map.h"
#include "core/os_file.h"
#include "core/symbols.h"
#include "symbol_fixture.h"

using namespace hx;
using symfix::Bytes;
using symfix::put;

namespace {

std::unique_ptr<Document> doc_of(const Bytes& b) { return Document::create_from_bytes("t", b.data(), b.size()); }

SymbolTable syms_of(const Document& d, const SymbolLimits& lim = {}) {
    return build_symbols(*d.snapshot(), detect_address_map(d), lim);
}

SymbolTable syms_of(const Bytes& b, const SymbolLimits& lim = {}) { return syms_of(*doc_of(b), lim); }

const Symbol* find(const SymbolTable& t, const std::string& label) {
    for (const Symbol& s : t.symbols)
        if (s.label() == label) return &s;
    return nullptr;
}

}  // namespace

TEST_CASE("symbols: PE32+ exports, forwarders, imports, delay imports") {
    const SymbolTable t = syms_of(symfix::make_pe(true));
    CHECK_FALSE(t.truncated);
    CHECK(t.note.empty());
    REQUIRE(t.symbols.size() == 5);
    REQUIRE(t.forwarders.size() == 1);

    const Symbol* a = find(t, "test.dll!Alpha");
    REQUIRE(a);
    CHECK(a->kind == Symbol::Export);
    CHECK(a->address == 0x140001000ull);
    CHECK(a->ordinal == 5);
    const Symbol* n = find(t, "test.dll!#6");  // exported by ordinal only
    REQUIRE(n);
    CHECK(n->address == 0x140001010ull);
    CHECK(n->ordinal == 6);
    CHECK(t.forwarders[0].name == "Fwd");
    CHECK(t.forwarders[0].forward == "NTDLL.RtlFoo");
    CHECK(t.forwarders[0].ordinal == 8);

    const Symbol* g = find(t, "KERNEL32.dll!GetProcAddress");
    REQUIRE(g);
    CHECK(g->kind == Symbol::Import);
    CHECK(g->address == 0x140002300ull);  // its IAT slot
    const Symbol* o = find(t, "KERNEL32.dll!#16");
    REQUIRE(o);
    CHECK(o->address == 0x140002308ull);
    CHECK(o->ordinal == 16);
    const Symbol* m = find(t, "USER32.dll!MessageBoxW");
    REQUIRE(m);
    CHECK(m->address == 0x140002340ull);

    // Sorted by address; exact and nearest lookups.
    for (size_t i = 1; i < t.symbols.size(); ++i) CHECK(t.symbols[i - 1].address <= t.symbols[i].address);
    CHECK(t.at(0x140001000ull) == a);
    CHECK(t.at(0x140001001ull) == nullptr);
    uint64_t delta = 0;
    CHECK(t.nearest(0x14000100Cull, &delta) == a);
    CHECK(delta == 0xC);
    CHECK(t.nearest(0x140001010ull, &delta) == n);
    CHECK(delta == 0);
    CHECK(t.nearest(0x140000FFFull) == nullptr);
    // Imports are data slots, never "nearest": past the IAT the last export is.
    CHECK(t.nearest(0x140002301ull, &delta) == n);
}

TEST_CASE("symbols: an entry point without a symbol is named \"entry\"") {
    Bytes b = symfix::make_pe();
    put(b, 0x58 + 16, 0x1020, 4);  // AddressOfEntryPoint: no export there
    SymbolTable t = syms_of(b);
    REQUIRE(t.symbols.size() == 6);
    REQUIRE(t.at(0x140001020ull));
    CHECK(t.at(0x140001020ull)->name == "entry");
    CHECK(t.at(0x140001020ull)->kind == Symbol::Function);
    Bytes e = symfix::make_elf();
    put(e, 24, 0x400250, 8);  // e_entry
    t = syms_of(e);
    REQUIRE(t.at(0x400250));
    CHECK(t.at(0x400250)->name == "entry");
    CHECK(syms_of(symfix::make_elf()).symbols.size() == 7);  // main is the entry: no extra name
}

TEST_CASE("symbols: PE32 4-byte thunks") {
    const SymbolTable t = syms_of(symfix::make_pe(false));
    REQUIRE(t.symbols.size() == 5);
    const Symbol* g = find(t, "KERNEL32.dll!GetProcAddress");
    REQUIRE(g);
    CHECK(g->address == 0x402300ull);
    const Symbol* o = find(t, "KERNEL32.dll!#16");
    REQUIRE(o);
    CHECK(o->address == 0x402304ull);
    CHECK(find(t, "USER32.dll!MessageBoxW"));
    CHECK(find(t, "test.dll!Alpha")->address == 0x401000ull);
}

TEST_CASE("symbols: ELF64 symtab, dynsym, GOT and PLT names") {
    const Bytes elf = symfix::make_elf();
    auto d = doc_of(elf);
    REQUIRE(detect_address_map(*d).kind == AddressMap::Elf);
    const SymbolTable t = syms_of(*d);
    CHECK_FALSE(t.truncated);
    CHECK(t.symbols.size() == 7);  // main once (symtab + dynsym deduplicated)
    const Symbol* m = t.at(0x400200);
    REQUIRE(m);
    CHECK(m->name == "main");
    CHECK(m->kind == Symbol::Function);
    CHECK(m->module.empty());
    CHECK(t.at(0x400240)->name == "helper");
    CHECK(t.at(0x400408)->name == "counter");
    CHECK(t.at(0x400408)->kind == Symbol::Object);
    CHECK(t.at(0x400410)->name == "puts@got");
    CHECK(t.at(0x400418)->name == "malloc@got");
    REQUIRE(t.at(0x400300));
    CHECK(t.at(0x400300)->name == "puts@plt");
    CHECK(t.at(0x400300)->kind == Symbol::Import);
    REQUIRE(t.at(0x400310));
    CHECK(t.at(0x400310)->name == "malloc@plt");
    uint64_t delta = 0;
    CHECK(t.nearest(0x400205, &delta)->name == "main");
    CHECK(delta == 5);

    // Big-endian / unknown machine: no @plt / @got guesses, the symtab stays.
    Bytes odd = elf;
    put(odd, 18, 183, 2);  // AArch64
    const SymbolTable u = syms_of(odd);
    CHECK(u.symbols.size() == 3);
    CHECK(u.at(0x400300) == nullptr);
}

TEST_CASE("symbols: ELF relocatable object is section-relative") {
    // ET_REL without program headers: .text at file offset 0x100; f = .text + 0x10.
    Bytes b(0x400, 0);
    std::memcpy(b.data(), "\x7F" "ELF", 4);
    b[4] = 2;
    b[5] = 1;
    put(b, 16, 1, 2);       // ET_REL
    put(b, 18, 62, 2);
    put(b, 40, 0x300, 8);   // shoff
    put(b, 58, 64, 2);
    put(b, 60, 4, 2);
    put(b, 62, 0, 2);       // no shstrtab
    auto sh = [&](size_t i, uint32_t type, uint64_t off, uint64_t size, uint32_t link, uint64_t entsize) {
        const size_t at = 0x300 + i * 64;
        put(b, at + 4, type, 4);
        put(b, at + 24, off, 8);
        put(b, at + 32, size, 8);
        put(b, at + 40, link, 4);
        put(b, at + 56, entsize, 8);
    };
    sh(1, 1, 0x100, 0x40, 0, 0);        // .text
    sh(2, 2, 0x200, 2 * 24, 3, 24);     // .symtab
    sh(3, 3, 0x280, 3, 0, 0);           // .strtab "\0f\0"
    b[0x281] = 'f';
    put(b, 0x200 + 24, 1, 4);
    b[0x200 + 24 + 4] = 0x12;
    put(b, 0x200 + 24 + 6, 1, 2);
    put(b, 0x200 + 24 + 8, 0x10, 8);
    auto d = doc_of(b);
    const AddressMap map = detect_address_map(*d);
    CHECK(map.kind == AddressMap::None);
    const SymbolTable t = build_symbols(*d->snapshot(), map);
    REQUIRE(t.symbols.size() == 1);
    CHECK(t.symbols[0].name == "f");
    CHECK(t.symbols[0].address == 0x110);
    // A manual base moves it like every other address.
    const SymbolTable m = build_symbols(*d->snapshot(), manual_address_map(*d, 0x8000));
    REQUIRE(m.symbols.size() == 1);
    CHECK(m.symbols[0].address == 0x8110);
    // The symbol cap counts symbols, not table entries (entry 0 is the null symbol), and a table
    // with more entries than the cap marks the result truncated instead of dropping them silently.
    SymbolLimits one;
    one.max_symbols = 1;
    const SymbolTable c1 = build_symbols(*d->snapshot(), map, one);
    REQUIRE(c1.symbols.size() == 1);
    CHECK(c1.symbols[0].name == "f");
    CHECK_FALSE(c1.truncated);
    put(b, 0x300 + 2 * 64 + 32, 3 * 24, 8);  // .symtab: one more (empty) entry
    auto d3 = doc_of(b);
    const SymbolTable c3 = build_symbols(*d3->snapshot(), detect_address_map(*d3), one);
    CHECK(c3.symbols.size() == 1);
    CHECK(c3.truncated);
    CHECK_FALSE(c3.note.empty());
}

TEST_CASE("symbols: none without a PE / ELF map, process memory, plain data") {
    auto pe = doc_of(symfix::make_pe());
    CHECK(build_symbols(*pe->snapshot(), no_address_map(*pe)).empty());
    CHECK(build_symbols(*pe->snapshot(), manual_address_map(*pe, 0x1000)).empty());
    auto elf = doc_of(symfix::make_elf());
    CHECK(build_symbols(*elf->snapshot(), no_address_map(*elf)).empty());  // ET_DYN needs its map
    CHECK(syms_of(Bytes(100, 0x90)).empty());
    CHECK(syms_of(Bytes{}).empty());
}

TEST_CASE("symbols: malformed tables stay bounded") {
    // Absurd export counts: capped, noted, nothing read out of range.
    Bytes b = symfix::make_pe();
    put(b, 0x400 + 20, 0xFFFFFFFFu, 4);  // NumberOfFunctions
    put(b, 0x400 + 24, 0xFFFFFFFFu, 4);  // NumberOfNames
    SymbolTable t = syms_of(b);
    CHECK_FALSE(t.note.empty());
    CHECK(find(t, "KERNEL32.dll!GetProcAddress"));  // the imports survive
    CHECK_FALSE(find(t, "test.dll!Alpha"));

    // Names without a NUL up to the end of the file: cut at the region end.
    b = symfix::make_pe();
    for (size_t i = 0x2110 - 0x2000 + 0x400; i < b.size(); ++i)
        if (b[i] == 0) b[i] = 'A';
    t = syms_of(b);
    for (const Symbol& s : t.symbols) CHECK(s.name.size() <= SymbolTable::kMaxName);

    // Import descriptors / thunks without terminators: stop at the section end.
    b = symfix::make_pe();
    for (size_t i = 0x600; i < 0x800; i += 4) put(b, i, 0x2300, 4);
    t = syms_of(b);
    CHECK(t.symbols.size() < 2000);

    // Caps: max_symbols.
    SymbolLimits lim;
    lim.max_symbols = 2;
    t = syms_of(symfix::make_pe(), lim);
    CHECK(t.truncated);
    CHECK(t.symbols.size() + t.forwarders.size() == 2);

    // A cancelled build ends early.
    std::atomic<bool> cancel{true};
    auto d = doc_of(symfix::make_pe());
    CHECK(build_symbols(*d->snapshot(), detect_address_map(*d), {}, &cancel).symbols.empty());

    // ELF symbol table claiming a huge size / entsize 0 / links out of range.
    Bytes e = symfix::make_elf();
    put(e, 0xE00 + 7 * 64 + 32, 0xFFFFFFFFFFFFull, 8);  // .symtab size
    put(e, 0xE00 + 4 * 64 + 40, 99, 4);                 // .dynsym link
    put(e, 0xE00 + 6 * 64 + 56, 0, 8);                  // .rela.plt entsize
    t = syms_of(e);
    CHECK(t.symbols.size() <= 7);
}

TEST_CASE("symbols: random corruption never crashes or reads out of range") {
    std::mt19937 rng(1234);
    const Bytes pe = symfix::make_pe(), elf = symfix::make_elf();
    for (int round = 0; round < 600; ++round) {
        Bytes b = (round & 1) ? pe : elf;
        const int flips = 1 + int(rng() % 24);
        for (int k = 0; k < flips; ++k) {
            const size_t at = rng() % b.size();
            b[at] = (rng() & 1) ? uint8_t(rng()) : uint8_t(0xFF);
        }
        if (round % 7 == 0) b.resize(rng() % b.size());
        const SymbolTable t = syms_of(b);
        CHECK(t.symbols.size() + t.forwarders.size() < 100000);
        for (const Symbol& s : t.symbols) CHECK(s.name.size() <= SymbolTable::kMaxName);
    }
}

TEST_CASE("symbols: background job keeps the old table until the new one is done") {
    auto d = doc_of(symfix::make_pe());
    SymbolJob job;
    CHECK(job.result().get() == nullptr);
    job.start(d->snapshot(), detect_address_map(*d));
    job.wait();
    REQUIRE(job.result().get() != nullptr);
    CHECK(job.result()->symbols.size() == 5);
    const uint64_t g = job.generation();
    auto e = doc_of(symfix::make_elf());
    job.start(e->snapshot(), detect_address_map(*e));
    job.wait();
    CHECK(job.generation() == g + 1);
    CHECK(job.result()->symbols.size() == 7);
    job.start(d->snapshot(), detect_address_map(*d));  // destroyed while running: joins cleanly
}

TEST_CASE("symbols: kernel32.dll (when present)") {
#ifdef _WIN32
    const std::string path = "C:\\Windows\\System32\\kernel32.dll";
    if (!os_stat(path).exists) return;
    std::string err;
    auto d = Document::open_file(path, &err);
    REQUIRE(d);
    const AddressMap map = detect_address_map(*d);
    REQUIRE(map.kind == AddressMap::Pe);
    const SymbolTable t = build_symbols(*d->snapshot(), map);
    CHECK_FALSE(t.truncated);
    size_t exports = t.forwarders.size(), imports = 0;
    for (const Symbol& s : t.symbols) {
        exports += s.kind == Symbol::Export;
        imports += s.kind == Symbol::Import;
    }
    MESSAGE("kernel32.dll: " << exports << " exports (" << t.forwarders.size() << " forwarded), " << imports
                             << " imports");
    CHECK(exports > 1000);
    CHECK(imports > 100);
    bool create_file = false;
    for (const Symbol& s : t.symbols) create_file |= s.label() == "KERNEL32.dll!CreateFileW";
    CHECK(create_file);
#endif
}
