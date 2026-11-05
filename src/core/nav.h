#pragma once
// Follow pointer + jump history (Back / Forward like a browser).
//
// The hex view reports a Ctrl+click on a byte as a follow request (ui/hex_view.h); the app decodes
// the pointer with decode_pointer(), pushes where it jumped from onto its NavHistory and moves the
// caret. Alt+Left / Alt+Right and the mouse X1/X2 buttons walk the history.
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace hx {

class Document;

// A caret position (+ selection length) to return to.
struct NavEntry {
    uint64_t offset = 0;
    uint64_t length = 0;  // selection length at `offset` (0 = just the caret)
    bool operator==(const NavEntry& o) const { return offset == o.offset && length == o.length; }
    bool operator!=(const NavEntry& o) const { return !(*this == o); }
};

// Back/forward stacks, at most kMax entries each (the oldest entries are dropped).
class NavHistory {
public:
    static constexpr size_t kMax = 200;

    // Records `from` (the position being left by a jump): pushed onto the back stack unless it
    // equals the entry on top, and the forward stack is cleared.
    void push(const NavEntry& from);
    bool can_back() const { return !back_.empty(); }
    bool can_forward() const { return !fwd_.empty(); }
    // Pops the back stack and returns that entry; `current` moves onto the forward stack.
    // Without history it returns `current` unchanged.
    NavEntry back(const NavEntry& current);
    // Mirror of back(): pops the forward stack, `current` moves onto the back stack.
    NavEntry forward(const NavEntry& current);
    void clear();

    const std::vector<NavEntry>& back_stack() const { return back_; }    // top = back()
    const std::vector<NavEntry>& forward_stack() const { return fwd_; }  // top = back()

private:
    std::vector<NavEntry> back_, fwd_;
};

// How a pointer is read: a `width`-byte integer (1, 2, 3, 4 or 8) in the given byte order,
// optionally sign-extended (is_signed).
//   absolute (default): target = value - base. A negative signed value cannot be followed.
//   relative:           target = at + value (self-relative offsets, rel32 displacements measured
//                       from the pointer itself); signed values can point backwards. base is unused.
struct PointerType {
    int width = 4;
    bool is_signed = false;
    bool big_endian = false;
    bool relative = false;
    uint64_t base = 0;
    bool operator==(const PointerType& o) const {
        return width == o.width && is_signed == o.is_signed && big_endian == o.big_endian &&
               relative == o.relative && base == o.base;
    }
    bool operator!=(const PointerType& o) const { return !(*this == o); }
};

bool valid_pointer_width(int width);  // 1, 2, 3, 4 or 8

// The follow-pointer width default of process documents. The width setting is global
// (Settings::pointer_width); while a process document is active its pointer size (8, or 4 for a
// WOW64 / 32-bit process) is put in its place, and the replaced width comes back when another
// kind of document becomes active - until the user picks a width (Inspector row, Follow Pointer
// Settings): from then on the user's choice holds everywhere for the rest of the session.
// settings.ini always keeps the user's width (persisted()).
struct AutoPointerWidth {
    bool picked = false;  // the user chose a width this session
    int saved = 0;        // the width an automatic one replaced (0 = no automatic width in effect)

    // The active document changed; `process_bytes` = its pointer size (4 / 8), 0 for anything but
    // a process document (or an unknown size). Updates `width` (the setting) in place.
    void activate(int process_bytes, int& width) {
        if (picked) return;
        if (process_bytes == 4 || process_bytes == 8) {
            if (!saved) saved = width;
            width = process_bytes;
        } else if (saved) {
            width = saved;
            saved = 0;
        }
    }
    // The user picked a width explicitly (it stays).
    void pick() {
        picked = true;
        saved = 0;
    }
    // The width to write to settings.ini: the replaced one while an automatic width is in effect.
    int persisted(int width) const { return saved ? saved : width; }
};

// Reads the pointer of `type` at `at` and turns it into a file offset (see PointerType). Returns
// false for an invalid width, bytes past EOF or unreadable (I/O error), a negative absolute value,
// value < base, a relative target before 0 or past 2^64, or target > doc.size() (target == size,
// the EOF position, is allowed). `target` is untouched on failure.
bool decode_pointer(const Document& doc, uint64_t at, const PointerType& type, uint64_t& target);
// Unsigned absolute pointer: decode_pointer(doc, at, {width, false, big_endian, false, base}, target).
bool decode_pointer(const Document& doc, uint64_t at, int width, bool big_endian, uint64_t base,
                    uint64_t& target);

// Short name of a pointer type, as shown in tooltips and the status bar: "u8", "u16 LE",
// "s32 BE", "u24 LE rel", "u64 LE, base 0x140000000" (base only for absolute pointers).
std::string pointer_type_name(const PointerType& type, bool uppercase = true);
// The Ctrl+hover tooltip line: "u16 LE -> 0x1234" when `ok`, else
// "u16 LE -> nothing to follow (beyond EOF, negative or unreadable)".
std::string pointer_link_text(const PointerType& type, bool ok, uint64_t target, bool uppercase = true);

}  // namespace hx
