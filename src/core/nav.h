#pragma once
// Follow pointer + jump history (Back / Forward like a browser).
//
// The hex view reports a Ctrl+click on a byte as a follow request (ui/hex_view.h); the app decodes
// the pointer with decode_pointer(), pushes where it jumped from onto its NavHistory and moves the
// caret. Alt+Left / Alt+Right and the mouse X1/X2 buttons walk the history.
#include <cstddef>
#include <cstdint>
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

// Reads an unsigned `width`-byte integer (1, 2, 4 or 8) at `at` and turns it into a file offset:
// target = value - base. Returns false for an invalid width, bytes past EOF or unreadable (I/O
// error), value < base, or target > doc.size() (target == size, the EOF position, is allowed).
bool decode_pointer(const Document& doc, uint64_t at, int width, bool big_endian, uint64_t base,
                    uint64_t& target);

}  // namespace hx
