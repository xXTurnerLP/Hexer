#include "core/disasm.h"

#include <Zydis/Zydis.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <initializer_list>
#include <string>
#include <vector>

#include "core/document.h"
#include "core/exe_map.h"
#include "core/util.h"

namespace hx {
namespace {

// Uppercase mode: everything but the "0x" prefixes ("MOV RAX, QWORD PTR [RIP+0x2A]").
void upcase(std::string& s) {
    for (size_t i = 0; i < s.size(); ++i) {
        const char c = s[i];
        if (c >= 'a' && c <= 'z' && !(c == 'x' && i > 0 && s[i - 1] == '0')) s[i] = char(c - 'a' + 'A');
    }
}

// One decoder + formatter for a batch of instructions with the same options.
struct Engine {
    ZydisDecoder dec;
    ZydisFormatter fmt;       // memory operands always show their size ("qword ptr")
    ZydisFormatter fmt_agen;  // ... except address computations (lea rcx, [rip+0x10])
    DisasmOptions opt;

    explicit Engine(const DisasmOptions& o) : opt(o) {
        const bool x64 = o.mode == DisasmMode::X64;
        ZydisDecoderInit(&dec, x64 ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LEGACY_32,
                         x64 ? ZYDIS_STACK_WIDTH_64 : ZYDIS_STACK_WIDTH_32);
        for (ZydisFormatter* f : {&fmt, &fmt_agen}) {
            ZydisFormatterInit(f, o.syntax == DisasmSyntax::Att ? ZYDIS_FORMATTER_STYLE_ATT : ZYDIS_FORMATTER_STYLE_INTEL);
            ZydisFormatterSetProperty(f, ZYDIS_FORMATTER_PROP_FORCE_RELATIVE_RIPREL, ZYAN_TRUE);
            ZydisFormatterSetProperty(f, ZYDIS_FORMATTER_PROP_ADDR_PADDING_ABSOLUTE, ZYDIS_PADDING_DISABLED);
            ZydisFormatterSetProperty(f, ZYDIS_FORMATTER_PROP_HEX_UPPERCASE, ZYAN_FALSE);  // see upcase()
        }
        ZydisFormatterSetProperty(&fmt, ZYDIS_FORMATTER_PROP_FORCE_SIZE, ZYAN_TRUE);
    }

    uint64_t mask(uint64_t a) const { return opt.mode == DisasmMode::X64 ? a : (a & 0xFFFFFFFFu); }

    std::string hex(uint64_t v) const { return "0x" + fmt_hex(v, 0, false); }

    void db(const uint8_t* p, size_t len, uint64_t address, Insn& out) const {
        out = Insn{};
        out.address = address;
        out.length = 1;
        if (len) {
            out.bytes[0] = p[0];
            out.text = "db 0x" + fmt_hex(p[0], 2, false);
            if (opt.uppercase) upcase(out.text);
        } else {
            out.length = 0;
        }
    }

    bool decode(const uint8_t* p, size_t len, uint64_t address, Insn& out) const {
        ZydisDecodedInstruction ins;
        ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
        if (!len || !ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, p, std::min<size_t>(len, Insn::kMaxLength), &ins, ops))) {
            db(p, len, address, out);
            return false;
        }
        out = Insn{};
        out.address = address;
        out.length = ins.length;
        out.valid = true;
        std::memcpy(out.bytes, p, ins.length);
        bool agen = false;
        for (uint8_t i = 0; i < ins.operand_count_visible; ++i)
            agen |= ops[i].type == ZYDIS_OPERAND_TYPE_MEMORY && ops[i].mem.type == ZYDIS_MEMOP_TYPE_AGEN;
        char buf[256];
        if (!ZYAN_SUCCESS(ZydisFormatterFormatInstruction(agen ? &fmt_agen : &fmt, &ins, ops, ins.operand_count_visible, buf,
                                                          sizeof buf, address, nullptr)))
            std::snprintf(buf, sizeof buf, "%s", "(?)");
        out.text = buf;
        switch (ins.meta.category) {
        case ZYDIS_CATEGORY_UNCOND_BR: out.flow = Insn::Jump; break;
        case ZYDIS_CATEGORY_COND_BR: out.flow = Insn::CondJump; break;
        case ZYDIS_CATEGORY_CALL: out.flow = Insn::Call; break;
        case ZYDIS_CATEGORY_RET: out.flow = Insn::Ret; break;
        case ZYDIS_CATEGORY_INTERRUPT:
        case ZYDIS_CATEGORY_SYSCALL: out.flow = Insn::Int; break;
        default: break;
        }
        // The first relative branch target or address-like memory operand.
        for (uint8_t i = 0; i < ins.operand_count_visible && !out.has_target; ++i) {
            const ZydisDecodedOperand& op = ops[i];
            ZyanU64 t = 0;
            if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && op.imm.is_relative) {
                if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&ins, &op, address, &t))) {
                    out.has_target = true;
                    out.target = mask(t);
                }
            } else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY && op.mem.index == ZYDIS_REGISTER_NONE &&
                       op.mem.segment != ZYDIS_REGISTER_FS && op.mem.segment != ZYDIS_REGISTER_GS &&
                       (op.mem.type == ZYDIS_MEMOP_TYPE_MEM || op.mem.type == ZYDIS_MEMOP_TYPE_AGEN)) {
                const bool riprel = op.mem.base == ZYDIS_REGISTER_RIP || op.mem.base == ZYDIS_REGISTER_EIP;
                if ((riprel || op.mem.base == ZYDIS_REGISTER_NONE) &&
                    ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&ins, &op, address, &t))) {
                    out.has_target = true;
                    out.target = mask(t);
                    if (riprel) out.text += std::string(opt.syntax == DisasmSyntax::Att ? "  # " : "  ; ") + hex(out.target);
                }
            }
        }
        if (opt.uppercase) upcase(out.text);
        return true;
    }

    // Length of the instruction at p (0 = invalid). No operands, no formatting.
    size_t length(const uint8_t* p, size_t len) const {
        ZydisDecodedInstruction ins;
        if (!len || !ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(&dec, nullptr, p, std::min<size_t>(len, Insn::kMaxLength), &ins)))
            return 0;
        return ins.length;
    }
};

}  // namespace

bool disasm_one(const uint8_t* data, size_t len, uint64_t address, const DisasmOptions& opt, Insn& out) {
    Engine e(opt);
    return e.decode(data, len, address, out);
}

void disasm_range(const Document& doc, uint64_t offset, size_t max_insns, const AddressMap& map,
                  const DisasmOptions& opt, std::vector<Insn>& out) {
    const uint64_t size = doc.size();
    if (!max_insns || offset >= size) return;
    const Engine e(opt);
    // Chunk: enough for the requested instructions (<= 15 bytes each), at most 64 KiB per read.
    const size_t chunk = size_t(std::clamp<uint64_t>(uint64_t(max_insns) * Insn::kMaxLength, 256, 64 << 10));
    std::vector<uint8_t> buf, bad;
    uint64_t buf_off = 0;
    uint64_t pos = offset;
    for (size_t count = 0; count < max_insns && pos < size; ++count) {
        const uint64_t need = std::min<uint64_t>(Insn::kMaxLength, size - pos);
        if (pos < buf_off || pos + need > buf_off + buf.size()) {
            const size_t n = size_t(std::min<uint64_t>(chunk, size - pos));
            buf.assign(n, 0);
            bad.assign(n, 0);
            buf.resize(doc.read(pos, buf.data(), n, bad.data()));
            bad.resize(buf.size());
            buf_off = pos;
            if (buf.empty()) break;
        }
        const size_t i = size_t(pos - buf_off);
        size_t avail = std::min<size_t>(buf.size() - i, Insn::kMaxLength);
        uint64_t va = pos;
        const bool mapped = map.offset_to_va(pos, va);
        if (!mapped) va = pos;
        Insn insn;
        if (bad[i]) {
            insn.address = va;
            insn.length = 1;
            insn.readable = false;
            insn.text = "??";
        } else {
            for (size_t k = 1; k < avail; ++k)
                if (bad[i + k]) {
                    avail = k;
                    break;
                }
            e.decode(buf.data() + i, avail, va, insn);
        }
        insn.offset = pos;
        insn.mapped = mapped;
        pos += insn.length ? insn.length : 1;
        out.push_back(std::move(insn));
    }
}

uint64_t disasm_sync_back(const Document& doc, uint64_t offset, size_t n, const DisasmOptions& opt, bool* landed) {
    if (landed) *landed = true;
    if (!n || !offset) return offset;
    if (landed) *landed = false;
    n = std::min<size_t>(n, 1024);
    const uint64_t size = doc.size();
    if (offset > size) offset = size;
    // At least kMinContext instructions of context even for small n: with only n * 15 bytes the
    // chains are too short to tell the real alignment (n = 1 picked a wrong start ~5% of the time
    // on real code; with 32 instructions of context ~0.03%).
    constexpr size_t kMinContext = 32;
    const size_t window = size_t(std::min<uint64_t>(offset, uint64_t(std::max(n, kMinContext)) * Insn::kMaxLength));
    const uint64_t start = offset - window;
    // Bytes [start, offset + 15): an instruction starting before `offset` may extend past it.
    const size_t total = size_t(std::min<uint64_t>(size - start, uint64_t(window) + Insn::kMaxLength));
    std::vector<uint8_t> buf(total), bad(total);
    const size_t got = doc.read(start, buf.data(), total, bad.data());
    if (got < window) return offset - std::min<uint64_t>(n, offset);
    const Engine e(opt);
    // Per start position i (relative to `start`): does its chain land on `window` (= offset), how
    // many instructions does it take, how many of them are invalid. Chains merge, so one pass from
    // the end computes all of them with a single decode per position.
    std::vector<uint32_t> depth(window, 0), invalid(window, 0);
    std::vector<uint8_t> lands(window, 0), lens(window, 1);
    for (size_t i = window; i-- > 0;) {
        if (bad[i]) continue;  // unreadable: no chain through here
        size_t avail = std::min<size_t>(got - i, Insn::kMaxLength);
        for (size_t k = 1; k < avail; ++k)
            if (bad[i + k]) {
                avail = k;
                break;
            }
        size_t len = e.length(buf.data() + i, avail);
        const bool inv = len == 0;
        if (inv) len = 1;  // shown as "db" by disasm_range: the listing continues after it
        lens[i] = uint8_t(len);
        const size_t next = i + len;
        if (next == window) {
            lands[i] = 1;
            depth[i] = 1;
            invalid[i] = inv;
        } else if (next < window && lands[next]) {
            lands[i] = 1;
            depth[i] = depth[next] + 1;
            invalid[i] = invalid[next] + inv;
        }
    }
    size_t best = window;
    for (size_t i = 0; i < window; ++i) {
        if (!lands[i]) continue;
        if (best == window || invalid[i] < invalid[best] || (invalid[i] == invalid[best] && depth[i] > depth[best]))
            best = i;
    }
    if (best == window) return offset - std::min<uint64_t>(n, offset);
    if (landed) *landed = true;
    // Walk the chain until n instructions remain before `offset`.
    size_t i = best;
    while (depth[i] > n) i += lens[i];
    return start + i;
}

std::string insn_bytes_hex(const Insn& insn, bool upper) {
    std::string s;
    for (int i = 0; i < insn.length && i < Insn::kMaxLength; ++i) {
        if (i) s += ' ';
        s += fmt_hex(insn.bytes[i], 2, upper);
    }
    return s;
}

const char* insn_flow_name(Insn::Flow f) {
    switch (f) {
    case Insn::Jump: return "jmp";
    case Insn::CondJump: return "jcc";
    case Insn::Call: return "call";
    case Insn::Ret: return "ret";
    case Insn::Int: return "int";
    default: return "";
    }
}

}  // namespace hx
