#include "core/multisel.h"

#include <algorithm>

#include "core/document.h"

namespace hx {

namespace {

bool fail(std::string* err, const std::string& msg) {
    if (err) *err = msg;
    return false;
}

std::string plural(uint64_t n, const char* one, const char* many) {
    return std::to_string(n) + " " + (n == 1 ? one : many);
}

}  // namespace

// ---- range sets ------------------------------------------------------------------------------

void range_add(std::vector<ByteRange>& set, ByteRange r) {
    if (r.end <= r.begin) return;
    // First range that ends at or after r.begin (touching counts), last that starts at or before r.end.
    auto lo = std::lower_bound(set.begin(), set.end(), r.begin,
                               [](const ByteRange& a, uint64_t b) { return a.end < b; });
    auto hi = std::upper_bound(lo, set.end(), r.end, [](uint64_t e, const ByteRange& a) { return e < a.begin; });
    if (lo == hi) {
        set.insert(lo, r);
        return;
    }
    lo->begin = std::min(lo->begin, r.begin);
    lo->end = std::max((hi - 1)->end, r.end);
    set.erase(lo + 1, hi);
}

size_t range_find(const std::vector<ByteRange>& set, uint64_t off) {
    auto it = std::upper_bound(set.begin(), set.end(), off, [](uint64_t o, const ByteRange& a) { return o < a.end; });
    return it != set.end() && it->begin <= off ? size_t(it - set.begin()) : set.size();
}

void range_clamp(std::vector<ByteRange>& set, uint64_t size) {
    while (!set.empty() && set.back().begin >= size) set.pop_back();
    if (!set.empty() && set.back().end > size) set.back().end = size;
}

uint64_t range_total(const std::vector<ByteRange>& set) {
    uint64_t n = 0;
    for (const ByteRange& r : set) n += r.len();
    return n;
}

std::vector<ByteRange> range_normalize(std::vector<ByteRange> v) {
    std::erase_if(v, [](const ByteRange& r) { return r.end <= r.begin; });
    if (!std::is_sorted(v.begin(), v.end(), [](const ByteRange& a, const ByteRange& b) { return a.begin < b.begin; }))
        std::sort(v.begin(), v.end(), [](const ByteRange& a, const ByteRange& b) { return a.begin < b.begin; });
    size_t out = 0;
    for (size_t i = 0; i < v.size(); ++i) {
        if (out && v[i].begin <= v[out - 1].end)
            v[out - 1].end = std::max(v[out - 1].end, v[i].end);
        else
            v[out++] = v[i];
    }
    v.resize(out);
    return v;
}

// ---- the selection of a document -------------------------------------------------------------

bool has_extra_selections(const ViewState& v) { return !v.extra_sel.empty(); }

std::vector<ByteRange> selection_ranges(const ViewState& v, uint64_t size) {
    std::vector<ByteRange> out = v.extra_sel;
    range_clamp(out, size);
    range_add(out, {std::min(v.sel_begin(), size), std::min(v.sel_end(), size)});
    return out;
}

std::vector<ByteRange> selection_ranges_primary_first(const ViewState& v, uint64_t size) {
    std::vector<ByteRange> all = selection_ranges(v, size);
    if (v.has_selection() && v.sel_begin() < size) {
        const size_t i = range_find(all, v.sel_begin());
        if (i < all.size()) std::rotate(all.begin(), all.begin() + std::ptrdiff_t(i), all.begin() + std::ptrdiff_t(i) + 1);
    }
    return all;
}

bool add_primary_to_extras(ViewState& v) {
    if (!v.has_selection()) return false;
    range_add(v.extra_sel, {v.sel_begin(), v.sel_end()});
    v.anchor = v.cursor;
    v.low_nibble = false;
    return true;
}

bool set_selection_ranges(ViewState& v, const std::vector<ByteRange>& ranges, uint64_t size, std::string* err) {
    if (ranges.size() > kMaxSelections)
        return fail(err, "too many ranges (" + std::to_string(ranges.size()) + "; at most " +
                             std::to_string(kMaxSelections) + ")");
    auto clamp = [size](ByteRange r) {
        r.begin = std::min(r.begin, size);
        r.end = std::clamp(r.end, r.begin, size);
        return r;
    };
    std::vector<ByteRange> extras;
    extras.reserve(ranges.size());
    for (size_t i = 1; i < ranges.size(); ++i) extras.push_back(clamp(ranges[i]));
    v.extra_sel = range_normalize(std::move(extras));
    const ByteRange p = ranges.empty() ? ByteRange{std::min(v.cursor, size), std::min(v.cursor, size)} : clamp(ranges[0]);
    v.anchor = p.begin;
    v.cursor = p.end;
    v.low_nibble = false;
    return true;
}

// ---- operations ------------------------------------------------------------------------------

bool erase_selections(Document& d, std::string* err) {
    const std::vector<ByteRange> rs = selection_ranges(d.view(), d.size());
    if (rs.empty()) return fail(err, "Nothing selected");
    if (!d.fill_ranges(rs, nullptr, 0, "Delete " + plural(rs.size(), "range", "ranges"), err)) return false;
    ViewState& v = d.view();
    v.cursor = v.anchor = std::min(rs.front().begin, d.size());
    v.low_nibble = false;
    v.extra_sel.clear();
    return true;
}

bool fill_selections(Document& d, const uint8_t* pattern, size_t pattern_len, std::string* err) {
    if (!pattern || pattern_len == 0) return fail(err, "Empty fill pattern");
    const std::vector<ByteRange> rs = selection_ranges(d.view(), d.size());
    if (rs.empty()) return fail(err, "Nothing selected");
    return d.fill_ranges(rs, pattern, pattern_len, "Fill " + plural(rs.size(), "range", "ranges"), err);
}

bool paste_selections(Document& d, const uint8_t* data, size_t len, std::string* err) {
    if (!data || len == 0) return fail(err, "Nothing to paste");
    const std::vector<ByteRange> rs = selection_ranges(d.view(), d.size());
    if (rs.empty()) return fail(err, "Nothing selected");
    for (const ByteRange& r : rs)
        if (r.len() != len)
            return fail(err, "The clipboard holds " + plural(len, "byte", "bytes") + " but the selection at " +
                                 "0x" + fmt_hex(r.begin, 8) + " is " + plural(r.len(), "byte", "bytes") +
                                 ": pasting into several ranges needs every range to have the pasted length");
    return d.fill_ranges(rs, data, len, "Paste into " + plural(rs.size(), "range", "ranges"), err);
}

size_t bookmark_selections(Document& d, std::string* err) {
    const std::vector<ByteRange> rs = selection_ranges(d.view(), d.size());
    std::string why;
    if (rs.empty())
        why = "Nothing selected";
    else if (rs.size() > kMaxSelectionBookmarks)
        why = "Bookmarking " + std::to_string(rs.size()) + " ranges is not supported (at most " +
              std::to_string(kMaxSelectionBookmarks) + ")";
    else if (d.busy())
        why = "A save is in progress";
    if (!why.empty()) {
        fail(err, why);
        return 0;
    }
    const size_t first = d.view().bookmarks.size() + 1;
    d.begin_group("Bookmark " + plural(rs.size(), "selection", "selections"));
    size_t added = 0;
    for (const ByteRange& r : rs) {
        Bookmark b;
        b.offset = r.begin;
        b.length = r.len();
        b.name = "Selection " + std::to_string(first + added);
        if (!d.add_bookmark(b)) break;
        ++added;
    }
    if (added == rs.size()) {
        d.end_group();
        return added;
    }
    d.abort_group();
    fail(err, "Could not add the bookmarks");
    return 0;
}

bool copy_selections(const Document& d, CopyFormat fmt, uint64_t max_bytes, std::string& out, std::string* err) {
    const std::vector<ByteRange> rs = selection_ranges(d.view(), d.size());
    if (rs.empty()) return fail(err, "Nothing selected");
    const uint64_t total = range_total(rs);
    if (total > max_bytes)
        return fail(err, "The " + std::to_string(rs.size()) + " ranges hold " + fmt_size(total) +
                             ". Copying more than " + fmt_size(max_bytes) + " as " + copy_format_name(fmt) +
                             " is not supported (the clipboard text is limited to 64 MiB).");
    out.clear();
    std::vector<uint8_t> buf;
    for (size_t i = 0; i < rs.size(); ++i) {
        buf.resize(size_t(rs[i].len()));
        const size_t n = d.read(rs[i].begin, buf.data(), buf.size());
        if (i) out += '\n';
        out += copy_as(buf.data(), n, fmt);
    }
    return true;
}

}  // namespace hx
