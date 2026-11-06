#pragma once
// Multi-selection: the primary selection (ViewState anchor / cursor, unchanged: the caret, the
// Inspector and the status bar's offset use it) plus extra ranges (ViewState::extra_sel). The
// operations below act on all of them as ONE undo step through Document; tools that need one
// contiguous range (Hash, Strings, Parse Selection, XOR guess) keep using the primary selection.
//
// The extra ranges are transient view state: not in undo entries (an undo restores the primary
// selection only and keeps the extras as they are) and not in the session. A plain click or Esc
// in the hex view clears them; edits do not move them (like bookmarks); a size change clamps them.
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "core/util.h"

namespace hx {

class Document;
struct ViewState;

// Half-open byte range [begin, end).
struct ByteRange {
    uint64_t begin = 0, end = 0;
    uint64_t len() const { return end - begin; }
    bool operator==(const ByteRange&) const = default;
};

// ---- range sets: sorted, non-empty, non-overlapping; ranges that touch or overlap are merged ----
// Adds `r` (ignored when empty), merging every range it touches.
void range_add(std::vector<ByteRange>& set, ByteRange r);
// Index of the range holding byte `off`, or set.size() if none. O(log n).
size_t range_find(const std::vector<ByteRange>& set, uint64_t off);
// Drops / trims the ranges past `size` (O(removed) from the back).
void range_clamp(std::vector<ByteRange>& set, uint64_t size);
uint64_t range_total(const std::vector<ByteRange>& set);
// Any ranges (unsorted, overlapping, empty ones) -> a range set. O(n log n), O(n) when sorted.
std::vector<ByteRange> range_normalize(std::vector<ByteRange> v);

// Most ranges a multi-selection holds (Select All Matches, doc:select_ranges).
constexpr size_t kMaxSelections = 100000;
// Most bookmarks bookmark_selections() adds at once (every undo step copies the bookmark list).
constexpr size_t kMaxSelectionBookmarks = 10000;

// ---- the selection of a document ---------------------------------------------------------------
bool has_extra_selections(const ViewState& v);
// What multi-selection operations act on: the primary selection (if not empty) and the extras,
// merged, in file order, clamped to `size`. Without extras just the primary selection (or {}).
std::vector<ByteRange> selection_ranges(const ViewState& v, uint64_t size);
// The same ranges with the one holding the primary selection first (doc:selections()).
std::vector<ByteRange> selection_ranges_primary_first(const ViewState& v, uint64_t size);
// Adds the primary selection to the extras and collapses it to the caret (Add Selection).
// False if the primary selection is empty.
bool add_primary_to_extras(ViewState& v);
// Sets the whole multi-selection: ranges[0] becomes the primary selection (caret at its end), the
// rest the extras. Ranges are clamped to `size`; empty ones are dropped (an empty first range
// still places the caret). False (and nothing changes) for more than kMaxSelections ranges.
bool set_selection_ranges(ViewState& v, const std::vector<ByteRange>& ranges, uint64_t size,
                          std::string* err = nullptr);

// ---- operations (each ONE undo step; false + *err when refused, the document unchanged) ---------
// Deletes every range ("Delete N ranges"); the caret goes to where the first one was, the extras
// are cleared (their offsets would be stale).
bool erase_selections(Document& d, std::string* err = nullptr);
// Fills every range with the repeating pattern, each range from the pattern's first byte
// ("Fill N ranges"). The selection stays.
bool fill_selections(Document& d, const uint8_t* pattern, size_t pattern_len, std::string* err = nullptr);
// Writes `data` over every range ("Paste into N ranges"); refused unless every range is exactly
// `len` bytes long. The selection stays.
bool paste_selections(Document& d, const uint8_t* data, size_t len, std::string* err = nullptr);
// One bookmark per range ("Selection 1"... numbered after the existing ones), ONE undo step
// ("Bookmark N selections"). Returns how many were added (0 + *err when refused: no ranges, more
// than kMaxSelectionBookmarks, busy).
size_t bookmark_selections(Document& d, std::string* err = nullptr);
// The ranges as clipboard text: each range formatted as `fmt` (copy_as), joined by '\n'. Refused
// when the ranges hold more than `max_bytes` bytes together.
bool copy_selections(const Document& d, CopyFormat fmt, uint64_t max_bytes, std::string& out,
                     std::string* err = nullptr);

}  // namespace hx
