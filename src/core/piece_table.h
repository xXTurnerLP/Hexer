#pragma once
// Piece table over (original file, append-only add buffer). Pure bookkeeping: knows nothing about
// the bytes themselves. All offsets are 64-bit.
#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

namespace hx {

struct Piece {
    enum Src : uint8_t { Original = 0, Add = 1 };
    Src src = Original;
    // Add pieces: AddBuffer chunk index (a piece never spans chunks).
    // Original pieces: index into Document's list of file versions (sources). Saving appends a new
    // version so undo history keeps referencing the bytes it was recorded against.
    uint32_t chunk = 0;
    uint64_t start = 0;   // offset in that file version, or offset inside the add chunk
    uint64_t len = 0;     // always > 0 for stored pieces

    bool operator==(const Piece&) const = default;
};

class PieceTable {
public:
    void reset(uint32_t source, uint64_t original_size);  // one Original piece [0, size) (or empty)
    void assign(std::vector<Piece> pieces);   // undo/redo/session restore; zero-length pieces dropped
    const std::vector<Piece>& pieces() const { return pieces_; }
    uint64_t size() const { return size_; }

    // Insert piece `p` at logical `pos` (pos <= size()). Merges with the previous piece when it is
    // contiguous in the same source/chunk (so typing does not explode the piece count).
    void insert(uint64_t pos, const Piece& p);
    // Remove [pos, pos+len), clamped to size().
    void erase(uint64_t pos, uint64_t len);

    // For pos < size(): {piece index, offset inside that piece}. Binary search, O(log n).
    std::pair<size_t, uint64_t> locate(uint64_t pos) const;
    uint64_t piece_start(size_t index) const { return starts_[index]; }  // logical start offset

    // True when the table is exactly the untouched file version `source`.
    bool is_identity(uint32_t source, uint64_t original_size) const;
    // True when size() == original_size and every Original piece is from `source` and sits at its
    // own offset, i.e. saving only needs to write the Add pieces in place (no file rewrite).
    bool is_inplace_compatible(uint32_t source, uint64_t original_size) const;

private:
    void rebuild();  // recompute starts_ and size_
    std::vector<Piece> pieces_;
    std::vector<uint64_t> starts_;
    uint64_t size_ = 0;
};

}  // namespace hx
