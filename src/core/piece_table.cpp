#include "core/piece_table.h"

#include <algorithm>

namespace hx {

namespace {
// b directly continues a in the same buffer, so the two can be one piece.
bool contiguous(const Piece& a, const Piece& b) {
    return a.src == b.src && a.chunk == b.chunk && a.start + a.len == b.start;
}

// Appends p to v, merging with the last piece when contiguous. Zero-length pieces are dropped.
void push_merged(std::vector<Piece>& v, const Piece& p) {
    if (p.len == 0) return;
    if (!v.empty() && contiguous(v.back(), p))
        v.back().len += p.len;
    else
        v.push_back(p);
}
}  // namespace

void PieceTable::reset(uint32_t source, uint64_t original_size) {
    pieces_.clear();
    if (original_size) pieces_.push_back(Piece{Piece::Original, source, 0, original_size});
    rebuild();
}

void PieceTable::assign(std::vector<Piece> pieces) {
    pieces_.clear();
    pieces_.reserve(pieces.size());
    for (const Piece& p : pieces) push_merged(pieces_, p);
    rebuild();
}

void PieceTable::insert(uint64_t pos, const Piece& p) {
    if (p.len == 0) return;
    pos = std::min(pos, size_);
    size_t idx = pieces_.size();
    if (pos < size_) {
        auto [i, off] = locate(pos);
        if (off) {
            Piece right = pieces_[i];
            right.start += off;
            right.len -= off;
            pieces_[i].len = off;
            pieces_.insert(pieces_.begin() + std::ptrdiff_t(i) + 1, right);
            idx = i + 1;
        } else {
            idx = i;
        }
    }
    if (idx > 0 && contiguous(pieces_[idx - 1], p)) {
        pieces_[idx - 1].len += p.len;
        if (idx < pieces_.size() && contiguous(pieces_[idx - 1], pieces_[idx])) {
            pieces_[idx - 1].len += pieces_[idx].len;
            pieces_.erase(pieces_.begin() + std::ptrdiff_t(idx));
        }
    } else if (idx < pieces_.size() && contiguous(p, pieces_[idx])) {
        pieces_[idx].start = p.start;
        pieces_[idx].len += p.len;
    } else {
        pieces_.insert(pieces_.begin() + std::ptrdiff_t(idx), p);
    }
    rebuild();
}

void PieceTable::erase(uint64_t pos, uint64_t len) {
    if (pos >= size_ || len == 0) return;
    len = std::min(len, size_ - pos);
    uint64_t end = pos + len;

    auto [i, off] = locate(pos);
    std::vector<Piece> out;
    out.reserve(pieces_.size() + 1);
    out.insert(out.end(), pieces_.begin(), pieces_.begin() + std::ptrdiff_t(i));
    if (off) {
        Piece left = pieces_[i];
        left.len = off;
        out.push_back(left);
    }
    if (end < size_) {
        auto [j, joff] = locate(end);
        Piece right = pieces_[j];
        right.start += joff;
        right.len -= joff;
        push_merged(out, right);
        out.insert(out.end(), pieces_.begin() + std::ptrdiff_t(j) + 1, pieces_.end());
    }
    pieces_ = std::move(out);
    rebuild();
}

std::pair<size_t, uint64_t> PieceTable::locate(uint64_t pos) const {
    auto it = std::upper_bound(starts_.begin(), starts_.end(), pos);
    size_t i = size_t(it - starts_.begin());
    if (i == 0) return {0, pos};  // only reachable when misused (empty table)
    --i;
    return {i, pos - starts_[i]};
}

bool PieceTable::is_identity(uint32_t source, uint64_t original_size) const {
    if (original_size == 0) return pieces_.empty();
    return pieces_.size() == 1 && pieces_[0].src == Piece::Original && pieces_[0].chunk == source &&
           pieces_[0].start == 0 && pieces_[0].len == original_size;
}

bool PieceTable::is_inplace_compatible(uint32_t source, uint64_t original_size) const {
    if (size_ != original_size) return false;
    for (size_t i = 0; i < pieces_.size(); ++i) {
        const Piece& p = pieces_[i];
        if (p.src == Piece::Original && (p.chunk != source || p.start != starts_[i])) return false;
    }
    return true;
}

void PieceTable::rebuild() {
    starts_.resize(pieces_.size());
    uint64_t pos = 0;
    for (size_t i = 0; i < pieces_.size(); ++i) {
        starts_[i] = pos;
        pos += pieces_[i].len;
    }
    size_ = pos;
}

}  // namespace hx
