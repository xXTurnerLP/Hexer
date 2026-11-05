#pragma once
// x86-64 / x86-32 disassembly (Zydis decoder + formatter; Zydis stays an implementation detail of
// disasm.cpp). Used by the Disassembly panel (ui/panel_disasm.h) and hx.disasm / doc:disasm.
//
// Text is Intel syntax by default ("mov rax, qword ptr [rip+0x1234]"), lowercase unless
// DisasmOptions::uppercase. Branch targets are printed as absolute addresses ("call 0x140001230");
// RIP-relative memory operands keep the relative form and get the resolved address as a comment
// ("lea rcx, [rip+0x2F5C]  ; 0x140004000"; AT&T: "# 0x..."). Insn::target holds that address.
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace hx {

class Document;
struct AddressMap;

enum class DisasmMode : uint8_t { X64, X86 };        // 64-bit long mode / 32-bit protected mode
enum class DisasmSyntax : uint8_t { Intel, Att };

struct DisasmOptions {
    DisasmMode mode = DisasmMode::X64;
    DisasmSyntax syntax = DisasmSyntax::Intel;
    bool uppercase = false;   // mnemonics, registers, hex digits
    bool operator==(const DisasmOptions&) const = default;
};

struct Insn {
    enum Flow : uint8_t { None, Jump, CondJump, Call, Ret, Int };  // Int: int / int3 / syscall / sysenter
    static constexpr int kMaxLength = 15;

    uint64_t offset = 0;      // file offset (disasm_range; disasm_one leaves 0)
    uint64_t address = 0;     // virtual address (the map's, else the offset)
    uint8_t length = 0;       // bytes (1 for "db" / "??" entries)
    bool valid = false;       // decoded; false: invalid byte ("db 0xNN") or unreadable ("??")
    bool readable = true;     // false: the byte could not be read (process hole, I/O error): "??"
    bool mapped = true;       // disasm_range: the offset lies inside the address map
    std::string text;         // formatted instruction (+ "  ; 0x..." for RIP-relative operands)
    bool has_target = false;  // branch target (relative branches) or memory operand address
    uint64_t target = 0;      //   (RIP-relative, or an absolute [disp] without base / index)
    Flow flow = None;
    uint8_t bytes[kMaxLength] = {};
};

// Decodes one instruction from data[0, len) at virtual address `address`. False if the bytes do
// not form a valid instruction (or len == 0): `out` then is the 1-byte entry "db 0xNN" (len > 0)
// with valid = false.
bool disasm_one(const uint8_t* data, size_t len, uint64_t address, const DisasmOptions& opt, Insn& out);

// Up to `max_insns` consecutive instructions from file offset `offset`, appended to `out`. Reads
// the document in bounded chunks (no more than ~max_insns * 15 bytes). Stops at EOF. Invalid bytes
// become 1-byte "db 0xNN" entries; unreadable bytes 1-byte "??" entries (readable = false); an
// instruction is never decoded across an unreadable byte. Addresses come from `map`
// (offset_to_va); offsets outside it keep address = offset and mapped = false.
void disasm_range(const Document& doc, uint64_t offset, size_t max_insns, const AddressMap& map,
                  const DisasmOptions& opt, std::vector<Insn>& out);

// Backward scrolling: x86 code has no instruction boundaries to find going backwards, so this
// guesses a start roughly `n` instructions before `offset` whose linear decode lands exactly on
// `offset` (offset stays an instruction start). Every byte position in the 15 * max(n, 32) bytes
// before `offset` is tried as a start; among the chains that land on `offset` the one with the fewest
// invalid / unreadable bytes and then the most instructions wins (more context = more likely the
// real alignment), and the instruction n steps before `offset` in it is returned (its earliest one
// when it has fewer). Limits: data mixed into code, padding, or deliberately overlapping
// instructions can make the chosen alignment differ from what a forward listing from an earlier
// point shows; it always returns some offset <= `offset`: offset itself for n == 0 or offset == 0,
// and offset - min(n, offset) as a last resort when no chain lands on `offset` (e.g. it lies inside
// the only plausible instruction; *landed = false then - list from `offset` itself if it must be an
// instruction start). Cost: one decode per byte of the window (n <= 1024).
uint64_t disasm_sync_back(const Document& doc, uint64_t offset, size_t n, const DisasmOptions& opt,
                          bool* landed = nullptr);

// "48 8B 05 2A 00 00 00" (uppercase hex unless `upper` is false).
std::string insn_bytes_hex(const Insn& insn, bool upper = true);
// "Call", "CondJump" ... as Lua sees it: "call", "jcc", "jmp", "ret", "int", "" for None.
const char* insn_flow_name(Insn::Flow f);

}  // namespace hx
