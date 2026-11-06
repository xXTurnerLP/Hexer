#include "core/symbols.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <initializer_list>
#include <memory>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace hx {
namespace {

// Bytes of the snapshot through a small window (names and table entries are mostly adjacent).
// Records which bytes the build used (SymbolTable::sources) and how its checks against the size
// came out (SymbolTable::size_min / size_max): every check goes through fits() / clamp_end().
class Reader {
public:
    explicit Reader(const Snapshot& s) : snap_(s), size_(s.size()) {}

    // [off, off + n) lies inside the document.
    bool fits(uint64_t off, uint64_t n) {
        const bool ok = off <= size_ && size_ - off >= n;
        if (ok) need_ = std::max(need_, off + n);
        else if (n <= UINT64_MAX - off) below_ = std::min(below_, off + n);  // fits from that size on
        return ok;
    }
    // min(end, size).
    uint64_t clamp_end(uint64_t end) {
        if (end <= size_) {
            need_ = std::max(need_, end);
            return end;
        }
        exact();
        return size_;
    }
    // The result depends on the exact size.
    void exact() {
        need_ = std::max(need_, size_);
        below_ = std::min(below_, size_ + 1);
    }
    // Every size in [size_min(), size_max()] passes / fails the same checks.
    uint64_t size_min() const { return need_; }
    uint64_t size_max() const { return below_ == UINT64_MAX ? UINT64_MAX : below_ - 1; }

    // Exactly n bytes at off; false past the end.
    bool read(uint64_t off, void* dst, size_t n) {
        if (!fetch(off, dst, n)) return false;
        note(off, n);
        return true;
    }
    bool uint(uint64_t off, int n, bool be, uint64_t& v) {
        uint8_t b[8];
        if (!read(off, b, size_t(n))) return false;
        v = 0;
        for (int i = 0; i < n; ++i) v = be ? (v << 8) | b[i] : v | (uint64_t(b[i]) << (8 * i));
        return true;
    }
    // NUL-terminated string at off, at most `max` bytes (cut there), control bytes -> '?'.
    std::string cstr(uint64_t off, size_t max) {
        std::string s;
        const uint64_t start = off;
        bool nul_seen = false;
        while (s.size() < max && off < size_) {
            uint8_t chunk[256];
            const size_t n = size_t(std::min<uint64_t>({sizeof chunk, max - s.size(), size_ - off}));
            if (!fetch(off, chunk, n)) break;
            const uint8_t* nul = static_cast<const uint8_t*>(std::memchr(chunk, 0, n));
            const size_t take = nul ? size_t(nul - chunk) : n;
            s.append(reinterpret_cast<const char*>(chunk), take);
            if (nul) {
                nul_seen = true;
                break;
            }
            off += n;
        }
        if (!nul_seen && s.size() < max && off >= size_) exact();  // cut by the end of the file
        note(start, s.size() + (nul_seen ? 1 : 0));  // the bytes looked at, not the whole chunk
        for (char& c : s)
            if (uint8_t(c) < 0x20 || uint8_t(c) == 0x7F) c = '?';
        return s;
    }
    // The recorded ranges, sorted and merged.
    std::vector<std::pair<uint64_t, uint64_t>> take_sources() {
        compact();
        return std::move(spans_);
    }

private:
    static constexpr size_t kWindow = 16 << 10;
    static constexpr uint64_t kGap = 64;  // ranges closer than this are merged (a superset is safe)

    void note(uint64_t off, uint64_t n) {
        if (!n) return;
        if (!spans_.empty() && off >= spans_.back().first && off <= spans_.back().second + kGap) {
            spans_.back().second = std::max(spans_.back().second, off + n);
            return;
        }
        spans_.emplace_back(off, off + n);
        if (spans_.size() >= compact_at_) {
            compact();
            compact_at_ = std::max<size_t>(4096, spans_.size() * 2);
        }
    }
    void compact() {
        std::sort(spans_.begin(), spans_.end());
        size_t k = 0;
        for (size_t i = 0; i < spans_.size(); ++i) {
            if (k && spans_[i].first <= spans_[k - 1].second + kGap)
                spans_[k - 1].second = std::max(spans_[k - 1].second, spans_[i].second);
            else
                spans_[k++] = spans_[i];
        }
        spans_.resize(k);
    }
    // read() without recording.
    bool fetch(uint64_t off, void* dst, size_t n) {
        if (!fits(off, n)) return false;
        if (n > kWindow) return snap_.read(off, static_cast<uint8_t*>(dst), n) == n;
        if (off < win_off_ || off - win_off_ + n > win_len_) {
            win_off_ = off;
            win_len_ = size_t(std::min<uint64_t>(kWindow, size_ - off));
            win_len_ = snap_.read(off, win_, win_len_);
            if (win_len_ < n) return false;
        }
        std::memcpy(dst, win_ + (off - win_off_), n);
        return true;
    }

    const Snapshot& snap_;
    uint64_t size_;
    uint8_t win_[kWindow];
    uint64_t win_off_ = 0;
    size_t win_len_ = 0;
    std::vector<std::pair<uint64_t, uint64_t>> spans_;  // [begin, end) read so far
    size_t compact_at_ = 4096;
    uint64_t need_ = 0;              // checks passed up to here (the size must stay >= it)
    uint64_t below_ = UINT64_MAX;    // a failed check would pass from this size on (MAX: none)
};

// Shared build state: caps, time budget, cancellation.
struct Ctx {
    Ctx(Reader& r, const AddressMap& m, const SymbolLimits& l, const std::atomic<bool>* c, SymbolTable& o)
        : rd(r), map(m), lim(l), cancel(c), out(o),
          deadline(std::chrono::steady_clock::now() + std::chrono::milliseconds(l.max_ms)) {}
    Reader& rd;
    const AddressMap& map;
    const SymbolLimits& lim;
    const std::atomic<bool>* cancel;
    SymbolTable& out;
    std::chrono::steady_clock::time_point deadline;
    uint64_t name_bytes = 0;
    unsigned ticks = 0;
    bool stopped = false;

    // True when the build must end (cap, time, cancel); checked once per table entry.
    bool stop() {
        if (stopped) return true;
        if (cancel && cancel->load(std::memory_order_relaxed)) return stopped = true;
        if (lim.max_ms > 0 && (++ticks & 255) == 0 && std::chrono::steady_clock::now() > deadline) {
            truncate("time limit reached");
            return true;
        }
        return false;
    }
    void truncate(const std::string& why) {
        if (!out.truncated) {
            out.truncated = true;
            add_note("truncated: " + why);
        }
        stopped = true;
    }
    void add_note(const std::string& n) {
        if (out.note.size() > 1024) return;
        if (!out.note.empty()) out.note += "; ";
        out.note += n;
    }
    std::string name(uint64_t off, size_t max = SymbolTable::kMaxName) { return rd.cstr(off, max); }
    // Adds a symbol (false once a cap is hit).
    bool add(Symbol s, bool forwarder = false) {
        if (stopped) return false;
        if (out.symbols.size() + out.forwarders.size() >= lim.max_symbols) {
            truncate("more than " + std::to_string(lim.max_symbols) + " symbols");
            return false;
        }
        name_bytes += s.name.size() + s.forward.size();
        if (name_bytes > SymbolTable::kMaxNameBytes) {
            truncate("names too large");
            return false;
        }
        (forwarder ? out.forwarders : out.symbols).push_back(std::move(s));
        return true;
    }
};

// ---- PE ------------------------------------------------------------------------------------------

struct PeInfo {
    bool plus = false;
    uint64_t base = 0;
    uint64_t dir_rva[16] = {}, dir_size[16] = {};
};

// `hdr`: offset of the DOS header (0 in a file; the load address of an image in process memory).
bool pe_info(Reader& rd, PeInfo& pi, uint64_t hdr = 0) {
    uint64_t lfanew = 0, sig = 0, opt_size = 0, magic = 0;
    if (!rd.uint(hdr + 0x3C, 4, false, lfanew)) return false;
    lfanew += hdr;
    if (!rd.uint(lfanew, 4, false, sig) || sig != 0x4550) return false;
    if (!rd.uint(lfanew + 20, 2, false, opt_size) || !rd.uint(lfanew + 24, 2, false, magic)) return false;
    const uint64_t opt = lfanew + 24;
    pi.plus = magic == 0x20B;
    if (!pi.plus && magic != 0x10B) return false;
    if (!rd.uint(opt + (pi.plus ? 24 : 28), pi.plus ? 8 : 4, false, pi.base)) return false;
    const uint64_t ndirs_at = opt + (pi.plus ? 108 : 92);
    uint64_t ndirs = 0;
    if (ndirs_at + 4 > opt + opt_size || !rd.uint(ndirs_at, 4, false, ndirs)) return true;  // no directories
    for (uint64_t i = 0; i < 16 && i < ndirs; ++i) {
        const uint64_t at = ndirs_at + 4 + i * 8;
        if (at + 8 > opt + opt_size) break;
        if (!rd.uint(at, 4, false, pi.dir_rva[i]) || !rd.uint(at + 4, 4, false, pi.dir_size[i])) break;
    }
    return true;
}

struct Pe {
    Pe(Ctx& ctx, const AddressMap& map) : c(ctx), m(map) {}
    Ctx& c;
    const AddressMap& m;  // this image's map (c.map, or one module of a process)
    PeInfo pi;

    // File offset of `rva` and how many file bytes follow it in the same region.
    bool span(uint64_t rva, uint64_t& off, uint64_t& avail) const {
        if (rva > UINT32_MAX || pi.base + rva < pi.base) return false;
        if (!m.va_to_offset(pi.base + rva, off)) return false;
        const MappedRegion* r = m.region_at_offset(off);
        if (!r) return false;
        avail = c.rd.clamp_end(r->offset + r->file_size) - off;
        return true;
    }
    bool off_of(uint64_t rva, uint64_t& off) const {
        uint64_t avail = 0;
        return span(rva, off, avail) && avail > 0;
    }
    std::string str(uint64_t rva, size_t max = SymbolTable::kMaxName) {
        uint64_t off = 0, avail = 0;
        if (!span(rva, off, avail) || !avail) return {};
        return c.name(off, size_t(std::min<uint64_t>(max, avail)));
    }
    // `n` entries of `width` bytes at `rva`, all inside one region.
    bool table(uint64_t rva, uint64_t n, int width, std::vector<uint64_t>& v) {
        uint64_t off = 0, avail = 0;
        if (!span(rva, off, avail) || avail / uint64_t(width) < n) return false;
        std::vector<uint8_t> raw(size_t(n) * size_t(width));
        if (!raw.empty() && !c.rd.read(off, raw.data(), raw.size())) return false;
        v.resize(size_t(n));
        for (size_t i = 0; i < v.size(); ++i) {
            uint64_t x = 0;
            for (int k = width - 1; k >= 0; --k) x = (x << 8) | raw[i * size_t(width) + size_t(k)];
            v[i] = x;
        }
        return true;
    }

    void exports() {
        const uint64_t dir = pi.dir_rva[0], dsize = pi.dir_size[0];
        if (!dir) return;
        std::vector<uint64_t> hdr;
        if (!table(dir, 10, 4, hdr)) return c.add_note("export directory not in the file");
        const std::string module = str(hdr[3], 256);
        const uint64_t ord_base = hdr[4];
        uint64_t nfunc = hdr[5], nnames = hdr[6];
        const uint64_t cap = c.lim.max_symbols;
        if (nfunc > cap || nnames > cap) {
            c.add_note("export directory: too many entries");
            nfunc = std::min(nfunc, cap);
            nnames = std::min(nnames, cap);
        }
        std::vector<uint64_t> eat, ent, eot;
        if (!table(hdr[7], nfunc, 4, eat)) return c.add_note("export address table not in the file");
        if (nnames && (!table(hdr[8], nnames, 4, ent) || !table(hdr[9], nnames, 2, eot))) {
            c.add_note("export name table not in the file");
            ent.clear();
            eot.clear();
        }
        std::vector<uint8_t> named(eat.size(), 0);
        auto add = [&](uint64_t idx, std::string name) {
            const uint64_t rva = eat[size_t(idx)];
            Symbol s;
            s.kind = Symbol::Export;
            s.name = std::move(name);
            s.module = module;
            s.ordinal = uint32_t(ord_base + idx);
            if (rva >= dir && rva - dir < dsize) {  // forwarder: the RVA points at "DLL.Function"
                s.forward = str(rva, 512);
                return c.add(std::move(s), true);
            }
            s.address = pi.base + rva;
            return c.add(std::move(s));
        };
        for (size_t j = 0; j < ent.size() && !c.stop(); ++j) {
            const uint64_t idx = eot[j];
            if (idx >= eat.size() || !eat[size_t(idx)]) continue;
            std::string name = str(ent[j]);
            if (name.empty()) continue;
            named[size_t(idx)] = 1;
            if (!add(idx, std::move(name))) return;
        }
        for (size_t i = 0; i < eat.size() && !c.stop(); ++i)
            if (!named[i] && eat[i] && !add(i, "#" + std::to_string(ord_base + i))) return;
    }

    // One import descriptor: names from `lookup` (INT / OriginalFirstThunk, else the IAT), one
    // symbol per IAT slot at `iat`.
    bool import_module(const std::string& dll, uint64_t lookup, uint64_t iat, bool rva_based) {
        const int ts = pi.plus ? 8 : 4;
        const uint64_t ord_flag = pi.plus ? (1ull << 63) : (1ull << 31);
        uint64_t off = 0, avail = 0;
        if (!span(lookup, off, avail)) return true;
        for (uint64_t i = 0; (i + 1) * uint64_t(ts) <= avail; ++i) {
            if (c.stop()) return false;
            uint64_t thunk = 0;
            if (!c.rd.uint(off + i * uint64_t(ts), ts, false, thunk) || !thunk) break;
            Symbol s;
            s.kind = Symbol::Import;
            s.module = dll;
            if (thunk & ord_flag) {
                s.ordinal = uint32_t(thunk & 0xFFFF);
                s.name = "#" + std::to_string(s.ordinal);
            } else {
                uint64_t rva = thunk & 0x7FFFFFFFu;
                if (!rva_based) rva = thunk >= pi.base ? thunk - pi.base : UINT32_MAX;
                if (rva < UINT32_MAX) s.name = str(rva + 2);  // skip the hint
                if (s.name.empty()) s.name = "?";
            }
            s.address = pi.base + iat + i * uint64_t(ts);
            if (!c.add(std::move(s))) return false;
        }
        return true;
    }

    void imports() {
        if (const uint64_t dir = pi.dir_rva[1]) {
            uint64_t off = 0, avail = 0;
            if (!span(dir, off, avail)) return c.add_note("import directory not in the file");
            for (uint64_t k = 0; k < SymbolTable::kMaxModules && (k + 1) * 20 <= avail; ++k) {
                if (c.stop()) return;
                uint8_t d[20];
                if (!c.rd.read(off + k * 20, d, sizeof d)) break;
                auto u32 = [&](int at) { return uint64_t(d[at]) | uint64_t(d[at + 1]) << 8 | uint64_t(d[at + 2]) << 16 | uint64_t(d[at + 3]) << 24; };
                const uint64_t oft = u32(0), name = u32(12), ft = u32(16);
                if (!name && !ft) break;  // the terminating descriptor
                if (!ft || (!oft && m.in_memory)) continue;  // a loaded IAT holds addresses, not names
                const std::string dll = str(name, 256);
                if (!import_module(dll.empty() ? "?" : dll, oft ? oft : ft, ft, true)) return;
            }
        }
        if (const uint64_t dir = pi.dir_rva[13]) {  // delay-load imports
            uint64_t off = 0, avail = 0;
            if (!span(dir, off, avail)) return;
            for (uint64_t k = 0; k < SymbolTable::kMaxModules && (k + 1) * 32 <= avail; ++k) {
                if (c.stop()) return;
                uint8_t d[32];
                if (!c.rd.read(off + k * 32, d, sizeof d)) break;
                auto u32 = [&](int at) { return uint64_t(d[at]) | uint64_t(d[at + 1]) << 8 | uint64_t(d[at + 2]) << 16 | uint64_t(d[at + 3]) << 24; };
                const bool rva_based = (u32(0) & 1) != 0;  // else (old VC6 format) VAs
                auto rva = [&](uint64_t v) { return rva_based ? v : (v >= pi.base ? v - pi.base : UINT64_MAX); };
                const uint64_t name = u32(4), iat = u32(12), lookup = u32(16);
                if (!name) break;
                if (!iat || !lookup || rva(iat) > UINT32_MAX) continue;
                const std::string dll = str(rva(name), 256);
                if (!import_module(dll.empty() ? "?" : dll, rva(lookup), rva(iat), rva_based)) return;
            }
        }
    }
};

// ---- ELF -----------------------------------------------------------------------------------------

struct Sh {
    uint64_t name = 0, type = 0, flags = 0, addr = 0, offset = 0, size = 0, link = 0, info = 0, entsize = 0;
    std::string sname;
};

struct Elf {
    explicit Elf(Ctx& ctx) : c(ctx) {}
    Ctx& c;
    bool is64 = false, be = false;
    uint64_t type = 0, machine = 0;
    std::vector<Sh> sh;
    std::vector<std::pair<uint64_t, std::string>> got;  // GOT slot -> symbol name (for @plt)

    bool get(uint64_t off, int n, uint64_t& v) { return c.rd.uint(off, n, be, v); }

    bool header() {
        uint8_t id[16];
        if (!c.rd.read(0, id, sizeof id) || std::memcmp(id, "\x7F" "ELF", 4) != 0) return false;
        if ((id[4] != 1 && id[4] != 2) || (id[5] != 1 && id[5] != 2)) return false;
        is64 = id[4] == 2;
        be = id[5] == 2;
        uint64_t shoff = 0, shentsize = 0, shnum = 0, shstrndx = 0;
        if (!get(16, 2, type) || !get(18, 2, machine)) return false;
        if (!get(is64 ? 40 : 32, is64 ? 8 : 4, shoff) || !get(is64 ? 58 : 46, 2, shentsize) ||
            !get(is64 ? 60 : 48, 2, shnum) || !get(is64 ? 62 : 50, 2, shstrndx))
            return false;
        const uint64_t need = is64 ? 64 : 40;
        if (!shnum || shnum > AddressMap::kMaxSections || shentsize < need) return false;
        if (!c.rd.fits(shoff, shnum * shentsize)) return false;  // shnum <= 1024: no overflow
        sh.resize(size_t(shnum));
        for (uint64_t i = 0; i < shnum; ++i) {
            const uint64_t at = shoff + i * shentsize;
            Sh& s = sh[size_t(i)];
            const int w = is64 ? 8 : 4;
            bool ok = get(at, 4, s.name) && get(at + 4, 4, s.type);
            if (is64)
                ok = ok && get(at + 8, 8, s.flags) && get(at + 16, 8, s.addr) && get(at + 24, 8, s.offset) &&
                     get(at + 32, 8, s.size) && get(at + 40, 4, s.link) && get(at + 44, 4, s.info) &&
                     get(at + 56, 8, s.entsize);
            else
                ok = ok && get(at + 8, w, s.flags) && get(at + 12, w, s.addr) && get(at + 16, w, s.offset) &&
                     get(at + 20, w, s.size) && get(at + 24, 4, s.link) && get(at + 28, 4, s.info) &&
                     get(at + 36, w, s.entsize);
            if (!ok) return false;
        }
        if (shstrndx < shnum) {
            const Sh& st = sh[size_t(shstrndx)];
            for (Sh& s : sh)
                if (s.name < st.size && c.rd.fits(st.offset, st.size))
                    s.sname = c.name(st.offset + s.name, size_t(std::min<uint64_t>(64, st.size - s.name)));
        }
        return true;
    }

    // File bytes of section `s` are inside the file (SHT_NOBITS has none).
    bool in_file(const Sh& s) const {
        return s.type != 8 && c.rd.fits(s.offset, s.size);
    }
    uint64_t sym_size() const { return is64 ? 24 : 16; }

    struct Sym {
        uint64_t name = 0, value = 0, info = 0, shndx = 0;
    };
    bool sym(const Sh& tab, uint64_t i, Sym& y) {
        const uint64_t es = std::max(tab.entsize, sym_size());
        const uint64_t at = tab.offset + i * es;
        if (is64)
            return get(at, 4, y.name) && get(at + 4, 1, y.info) && get(at + 6, 2, y.shndx) && get(at + 8, 8, y.value);
        return get(at, 4, y.name) && get(at + 4, 4, y.value) && get(at + 12, 1, y.info) && get(at + 14, 2, y.shndx);
    }
    std::string sym_name(const Sh& tab, const Sym& y) {
        if (tab.link >= sh.size()) return {};
        const Sh& str = sh[size_t(tab.link)];
        if (!in_file(str) || y.name >= str.size) return {};
        return c.name(str.offset + y.name, size_t(std::min<uint64_t>(SymbolTable::kMaxName, str.size - y.name)));
    }
    // Entries of `tab` to walk: at most the symbol cap + the null entry 0; more mark the result
    // truncated (the entries past the cap are never read).
    uint64_t count(const Sh& tab, uint64_t min_entsize) const {
        const uint64_t es = std::max(tab.entsize, min_entsize);
        if (!in_file(tab)) return 0;
        const uint64_t n = tab.size / es, cap = uint64_t(c.lim.max_symbols) + 1;
        if (n <= cap) return n;
        if (!c.out.truncated) {
            c.out.truncated = true;
            c.add_note("truncated: an ELF table has more than " + std::to_string(c.lim.max_symbols) + " entries");
        }
        return cap;
    }

    void symtabs() {
        const bool rel = type == 1;
        if (!rel && (type != 2 && type != 3)) return;
        if (!rel && c.map.kind != AddressMap::Elf) return;
        for (const Sh& tab : sh) {
            if (tab.type != 2 && tab.type != 11) continue;  // SHT_SYMTAB, SHT_DYNSYM
            const uint64_t n = count(tab, sym_size());
            for (uint64_t i = 1; i < n; ++i) {
                if (c.stop()) return;
                Sym y;
                if (!sym(tab, i, y)) break;
                const uint64_t st = y.info & 0xF;
                if (st != 1 && st != 2 && st != 10) continue;  // OBJECT, FUNC, GNU_IFUNC
                if (!y.value || !y.shndx || y.shndx >= 0xFF00) continue;
                uint64_t va = y.value;
                if (rel) {
                    if (y.shndx >= sh.size() || !in_file(sh[size_t(y.shndx)])) continue;
                    const uint64_t off = sh[size_t(y.shndx)].offset + y.value;
                    if (off < y.value || !c.map.offset_to_va(off, va)) continue;
                }
                Symbol s;
                s.kind = st == 1 ? Symbol::Object : Symbol::Function;
                s.name = sym_name(tab, y);
                if (s.name.empty()) continue;
                s.address = va;
                if (!c.add(std::move(s))) return;
            }
        }
    }

    void relocs() {
        if ((type != 2 && type != 3) || c.map.kind != AddressMap::Elf || (machine != 62 && machine != 3)) return;
        for (const Sh& rs : sh) {
            if (rs.type != 4 && rs.type != 9) continue;  // SHT_RELA, SHT_REL
            if (rs.link >= sh.size()) continue;
            const Sh& tab = sh[size_t(rs.link)];
            if (tab.type != 11 && tab.type != 2) continue;
            const bool rela = rs.type == 4;
            const uint64_t es_min = is64 ? (rela ? 24 : 16) : (rela ? 12 : 8);
            const uint64_t es = std::max(rs.entsize, es_min);
            const uint64_t n = count(rs, es_min);
            const uint64_t nsyms = count(tab, sym_size());
            for (uint64_t i = 0; i < n; ++i) {
                if (c.stop()) return;
                const uint64_t at = rs.offset + i * es;
                uint64_t where = 0, info = 0;
                if (!get(at, is64 ? 8 : 4, where) || !get(at + (is64 ? 8 : 4), is64 ? 8 : 4, info)) break;
                const uint64_t rtype = is64 ? (info & 0xFFFFFFFFu) : (info & 0xFF);
                const uint64_t symi = is64 ? (info >> 32) : (info >> 8);
                if ((rtype != 7 && rtype != 6) || !symi || symi >= nsyms) continue;  // JUMP_SLOT, GLOB_DAT
                Sym y;
                if (!sym(tab, symi, y)) continue;
                std::string name = sym_name(tab, y);
                if (name.empty()) continue;
                got.emplace_back(where, name);
                Symbol s;
                s.kind = Symbol::Import;
                s.name = name + "@got";
                s.address = where;
                if (!c.add(std::move(s))) return;
            }
        }
        std::sort(got.begin(), got.end());
    }

    // "jmp [rip+X]" (x86-64) / "jmp [X]" (i386) through a GOT slot -> "name@plt" at that stub.
    void plt() {
        if (got.empty()) return;
        constexpr uint64_t kMaxPlt = 1 << 20;
        for (const Sh& s : sh) {
            if (s.sname != ".plt" && s.sname != ".plt.sec" && s.sname != ".plt.got") continue;
            if (!in_file(s) || s.size < 6 || s.size > kMaxPlt) continue;
            std::vector<uint8_t> b(size_t(s.size));
            if (!c.rd.read(s.offset, b.data(), b.size())) continue;
            for (size_t p = 0; p + 6 <= b.size(); ++p) {
                if (b[p] != 0xFF || b[p + 1] != 0x25) continue;
                if (c.stop()) return;
                const uint32_t d = uint32_t(b[p + 2]) | uint32_t(b[p + 3]) << 8 | uint32_t(b[p + 4]) << 16 |
                                   uint32_t(b[p + 5]) << 24;
                const uint64_t target = is64 ? s.addr + p + 6 + uint64_t(int64_t(int32_t(d))) : uint64_t(d);
                auto it = std::lower_bound(got.begin(), got.end(), std::make_pair(target, std::string()));
                if (it == got.end() || it->first != target) continue;
                size_t entry = p;
                if (entry >= 1 && b[entry - 1] == 0xF2) --entry;  // bnd
                if (entry >= 4 && b[entry - 4] == 0xF3 && b[entry - 3] == 0x0F && b[entry - 2] == 0x1E &&
                    (b[entry - 1] == 0xFA || b[entry - 1] == 0xFB))
                    entry -= 4;  // endbr64 / endbr32
                Symbol sym;
                sym.kind = Symbol::Import;
                sym.name = it->second + "@plt";
                sym.address = s.addr + entry;
                if (!c.add(std::move(sym))) return;
                p += 5;
            }
        }
    }
};

}  // namespace

const char* symbol_kind_name(Symbol::Kind k) {
    switch (k) {
    case Symbol::Export: return "export";
    case Symbol::Function: return "function";
    case Symbol::Object: return "object";
    case Symbol::Import: return "import";
    }
    return "";
}

void SymbolTable::finalize() {
    auto key = [](const Symbol& s) { return std::tie(s.address, s.kind, s.name, s.module); };
    std::sort(symbols.begin(), symbols.end(), [&](const Symbol& a, const Symbol& b) { return key(a) < key(b); });
    symbols.erase(std::unique(symbols.begin(), symbols.end(), [&](const Symbol& a, const Symbol& b) { return key(a) == key(b); }),
                  symbols.end());
    code_.clear();
    for (size_t i = 0; i < symbols.size(); ++i)
        if (symbols[i].kind != Symbol::Import) code_.push_back(uint32_t(i));
}

const Symbol* SymbolTable::at(uint64_t va) const {
    auto it = std::lower_bound(symbols.begin(), symbols.end(), va,
                               [](const Symbol& s, uint64_t v) { return s.address < v; });
    return it != symbols.end() && it->address == va ? &*it : nullptr;
}

const Symbol* SymbolTable::nearest(uint64_t va, uint64_t* delta) const {
    // The last non-import symbol with address <= va; among several at that address the first.
    auto it = std::upper_bound(code_.begin(), code_.end(), va,
                               [this](uint64_t v, uint32_t i) { return v < symbols[i].address; });
    if (it == code_.begin()) return nullptr;
    const uint64_t addr = symbols[*(it - 1)].address;
    while (it != code_.begin() && symbols[*(it - 1)].address == addr) --it;
    if (delta) *delta = va - addr;
    return &symbols[*it];
}

namespace {

void append_lower(std::string& dst, const std::string& s) {
    for (char c : s) dst += char(c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c);
}

}  // namespace

void SymbolTable::index_labels() {
    size_t total = 0;
    for (const Symbol& s : symbols) total += s.module.size() + s.name.size() + 2;
    lower_.clear();
    lower_.reserve(total);
    lower_at_.clear();
    lower_at_.reserve(symbols.size() + 1);
    for (const Symbol& s : symbols) {
        lower_at_.push_back(lower_.size());
        if (!s.module.empty()) {
            append_lower(lower_, s.module);
            lower_ += '!';
        }
        append_lower(lower_, s.name);
        lower_ += '\n';  // never inside a label (control bytes became '?'): no match spans two
    }
    lower_at_.push_back(lower_.size());
}

void SymbolTable::match(std::string_view filter, std::vector<uint32_t>& out) const {
    out.clear();
    std::string f;
    append_lower(f, std::string(filter));
    if (f.empty()) {
        out.reserve(symbols.size());
        for (size_t i = 0; i < symbols.size(); ++i) out.push_back(uint32_t(i));
        return;
    }
    if (f.find('\n') != std::string::npos) return;
    if (lower_at_.size() != symbols.size() + 1) {  // not indexed: lowercase label by label
        std::string l;
        for (size_t i = 0; i < symbols.size(); ++i) {
            l.clear();
            append_lower(l, symbols[i].label());
            if (l.find(f) != std::string::npos) out.push_back(uint32_t(i));
        }
        return;
    }
    // One scan of the whole text; after a hit, continue at the next label.
    const std::string_view text(lower_);
    size_t i = 0;
    for (size_t pos = text.find(f); pos != std::string_view::npos; pos = text.find(f, lower_at_[i + 1])) {
        while (lower_at_[i + 1] <= pos) ++i;
        out.push_back(uint32_t(i));
    }
}

bool same_bytes(const Snapshot& a, const Snapshot& b, const std::vector<std::pair<uint64_t, uint64_t>>& ranges) {
    // Where byte `pos` of a snapshot comes from: piece `i`, `o` bytes into it.
    struct Cursor {
        const Snapshot& s;
        size_t i = 0;
        uint64_t o = 0;
        void seek(uint64_t pos) {
            i = size_t(std::upper_bound(s.starts.begin(), s.starts.end(), pos) - s.starts.begin()) - 1;
            o = pos - s.starts[i];
        }
        const void* origin() const {
            const Piece& p = s.pieces[i];
            if (p.src == Piece::Original) return p.chunk < s.sources.size() ? s.sources[p.chunk].get() : nullptr;
            return p.chunk < s.chunks.size() ? s.chunks[p.chunk].get() : nullptr;
        }
        bool same(const Cursor& c) const {
            const Piece &p = s.pieces[i], &q = c.s.pieces[c.i];
            return p.src == q.src && origin() == c.origin() && p.start + o == q.start + c.o;
        }
        uint64_t left() const { return s.pieces[i].len - o; }
        void advance(uint64_t n) {
            o += n;
            if (o == s.pieces[i].len) {
                ++i;
                o = 0;
            }
        }
    };
    if (a.pieces.size() != a.starts.size() || b.pieces.size() != b.starts.size()) return false;
    for (const auto& [begin, range_end] : ranges) {
        const uint64_t end = std::min(range_end, a.size());
        if (begin >= end) continue;
        if (end > b.size()) return false;  // b has fewer bytes
        Cursor x{a}, y{b};
        x.seek(begin);
        y.seek(begin);
        for (uint64_t pos = begin; pos < end;) {
            if (x.i >= a.pieces.size() || y.i >= b.pieces.size() || !x.same(y)) return false;
            const uint64_t n = std::min({x.left(), y.left(), end - pos});
            x.advance(n);
            y.advance(n);
            pos += n;
        }
    }
    return true;
}

SymbolTable build_symbols(const Snapshot& snap, const AddressMap& map, const SymbolLimits& lim,
                          const std::atomic<bool>* cancel) {
    SymbolTable out;
    auto rd = std::make_unique<Reader>(snap);  // the window buffer is too big for a worker's stack
    Ctx c(*rd, map, lim, cancel, out);
    std::vector<Symbol> entries;  // process modules: "module!entry" unless named otherwise
    if (map.kind == AddressMap::Process) {
        // Every loaded module (map.names) through its in-memory PE headers.
        for (const MappedRegion& mod : map.names) {
            if (c.stop()) break;
            AddressMap image;
            if (!detect_pe_image(snap, mod.address, image)) continue;
            Pe pe(c, image);
            if (!pe_info(*rd, pe.pi, mod.address)) continue;
            pe.pi.base = mod.address;  // the load address, whatever the header's ImageBase says
            pe.exports();
            pe.imports();
            if (image.has_entry) {
                Symbol s;
                s.kind = Symbol::Function;
                s.name = "entry";
                s.module = mod.name;
                s.address = image.entry;
                entries.push_back(std::move(s));
            }
        }
    } else if (map.kind == AddressMap::Pe) {
        Pe pe(c, map);
        if (pe_info(*rd, pe.pi, map.in_memory ? map.base : 0)) {
            if (map.in_memory) pe.pi.base = map.base;
            pe.exports();
            pe.imports();
        }
    } else {
        Elf elf(c);
        if (elf.header()) {
            elf.symtabs();
            elf.relocs();
            elf.plt();
        }
    }
    out.finalize();
    // A stripped image still gets its entry point named.
    const bool cancelled = cancel && cancel->load();
    std::vector<Symbol> unnamed;  // module entry points without a symbol of their own
    for (Symbol& s : entries)
        if (!cancelled && !out.at(s.address)) unnamed.push_back(std::move(s));
    for (Symbol& s : unnamed)
        if (out.symbols.size() < lim.max_symbols) out.symbols.push_back(std::move(s));
    if (!unnamed.empty()) out.finalize();
    if ((map.kind == AddressMap::Pe || map.kind == AddressMap::Elf) && map.has_entry && !cancelled &&
        !out.at(map.entry) && out.symbols.size() < lim.max_symbols) {
        Symbol s;
        s.kind = Symbol::Function;
        s.name = "entry";
        s.address = map.entry;
        out.symbols.push_back(std::move(s));
        out.finalize();
    }
    out.sources = rd->take_sources();
    out.size_min = rd->size_min();
    out.size_max = rd->size_max();
    return out;
}

// ---- SymbolJob -----------------------------------------------------------------------------------

namespace {

bool same_region(const MappedRegion& a, const MappedRegion& b) {
    return a.offset == b.offset && a.file_size == b.file_size && a.address == b.address && a.mem_size == b.mem_size &&
           a.name == b.name && a.exec == b.exec;
}

bool same_regions(const std::vector<MappedRegion>& a, const std::vector<MappedRegion>& b) {
    return std::equal(a.begin(), a.end(), b.begin(), b.end(), same_region);
}

// For the symbols: a Pe / Elf map's file_size (the document size) is not used by build_symbols
// (it goes by the regions, which hold the size wherever it cut them); the size window of the
// table (SymbolTable::size_min / size_max) covers the rest.
bool same_map(const AddressMap& a, const AddressMap& b) {
    const bool by_regions = a.kind == AddressMap::Pe || a.kind == AddressMap::Elf;
    return a.kind == b.kind && a.base == b.base && (by_regions || a.file_size == b.file_size) &&
           a.has_entry == b.has_entry &&
           a.entry == b.entry && a.bits == b.bits && a.format == b.format && a.in_memory == b.in_memory &&
           same_regions(a.regions, b.regions) && same_regions(a.names, b.names);
}

}  // namespace

SymbolJob::~SymbolJob() {
    {
        std::lock_guard<std::mutex> lk(mu_);
        quit_ = true;
        cancel_ = true;
    }
    cv_.notify_all();
    if (thread_.joinable()) thread_.join();
}

bool SymbolJob::start(std::shared_ptr<const Snapshot> snap, AddressMap map, SymbolLimits lim) {
    std::vector<uint64_t> epochs;
    if (snap)
        for (const auto& src : snap->sources) epochs.push_back(src ? src->epoch() : 0);
    {
        std::lock_guard<std::mutex> lk(mu_);
        const Request& last = result_for_;
        const bool live = map.kind == AddressMap::Process || map.in_memory;  // bytes change without edits
        if (!live && !has_pending_ && !busy_ && result_ && !result_->truncated && snap && last.snap &&
            lim.max_symbols == last.lim.max_symbols && lim.max_ms == last.lim.max_ms && epochs == last.epochs &&
            snap->size() >= result_->size_min && snap->size() <= result_->size_max && same_map(map, last.map) &&
            same_bytes(*last.snap, *snap, result_->sources)) {
            result_for_.snap.swap(snap);  // the newer snapshot (the old one is released below, unlocked)
            return false;
        }
        pending_.snap.swap(snap);  // a request the worker has not picked up yet is replaced
        pending_.map = std::move(map);
        pending_.lim = lim;
        pending_.epochs = std::move(epochs);
        has_pending_ = true;
        ++requests_;
        cancel_ = true;  // the running build (if any) stops and is dropped
        if (!thread_.joinable()) thread_ = std::thread([this] { worker(); });
    }
    cv_.notify_all();
    return true;
}

void SymbolJob::worker() {
    std::unique_lock<std::mutex> lk(mu_);
    for (;;) {
        cv_.wait(lk, [this] { return quit_ || has_pending_; });
        if (quit_) return;
        Request r = std::move(pending_);
        pending_ = Request{};
        has_pending_ = false;
        busy_ = true;
        cancel_ = false;
        const uint64_t id = requests_;
        lk.unlock();
        auto t = std::make_shared<SymbolTable>(build_symbols(*r.snap, r.map, r.lim, &cancel_));
        t->index_labels();
        std::shared_ptr<const SymbolTable> old_table;
        Request old_req;
        lk.lock();
        busy_ = false;
        if (!cancel_.load()) {  // cancel_ is only reset here, so false = never cancelled: complete
            old_table = std::move(result_);
            old_req = std::move(result_for_);
            result_ = std::move(t);
            result_for_ = std::move(r);
            result_request_ = id;
        }
        ++generation_;
        cv_.notify_all();
        // Free the replaced / dropped table and snapshots without holding the lock (1M symbols).
        lk.unlock();
        t.reset();
        r = Request{};
        old_table.reset();
        old_req = Request{};
        lk.lock();
    }
}

bool SymbolJob::running() const {
    std::lock_guard<std::mutex> lk(mu_);
    return has_pending_ || busy_;
}

void SymbolJob::wait() {
    std::unique_lock<std::mutex> lk(mu_);
    cv_.wait(lk, [this] { return !has_pending_ && !busy_; });
}

std::shared_ptr<const SymbolTable> SymbolJob::result() const {
    std::lock_guard<std::mutex> lk(mu_);
    return result_;
}

bool SymbolJob::current() const {
    std::lock_guard<std::mutex> lk(mu_);
    return result_ && !has_pending_ && !busy_ && result_request_ == requests_;
}

uint64_t SymbolJob::builds() const {
    std::lock_guard<std::mutex> lk(mu_);
    return requests_;
}

}  // namespace hx
