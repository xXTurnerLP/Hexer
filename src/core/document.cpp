#include "core/document.h"

#include <algorithm>
#include <chrono>
#include <cstring>

namespace hx {

namespace {

std::atomic<uint64_t> g_next_doc_id{1};

// App-wide policies (Document::set_undo_merge / set_backup_policy).
std::atomic<int> g_merge_ms{500};
std::atomic<uint64_t> g_merge_max_bytes{32};
std::atomic<bool> g_backup_enabled{true};
std::atomic<uint64_t> g_backup_max_bytes{4ull << 30};

int64_t steady_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}
std::atomic<int64_t (*)()> g_clock{&steady_ms};

constexpr size_t kSaveBlock = 4u << 20;              // streaming block for rewrite saves
constexpr size_t kPreserveBlock = 1u << 20;          // in-place save: copy old bytes in 1 MiB pieces
constexpr uint64_t kMaxPreserve = 512ull << 20;      // above this, history is trimmed instead
constexpr uint64_t kMaxMaterialize = 16ull << 20;    // persist(): inline bytes of old file versions
constexpr uint64_t kFillMaxUnit = 64ull << 20;       // fill(): largest pattern chunk

bool fail(std::string* err, const std::string& msg) {
    if (err) *err = msg;
    return false;
}

struct BusyGuard {
    std::atomic<bool>& flag;
    ~BusyGuard() { flag = false; }
};

// Clears Progress::committing when a save phase ends (success or failure).
struct CommitGuard {
    Progress* p;
    void begin() {
        if (p) p->committing = true;
    }
    ~CommitGuard() {
        if (p) p->committing = false;
    }
};

struct Range {
    uint64_t off, len;
    uint64_t end() const { return off + len; }
};

void merge_ranges(std::vector<Range>& v) {
    std::sort(v.begin(), v.end(), [](const Range& a, const Range& b) { return a.off < b.off; });
    std::vector<Range> out;
    for (const Range& r : v) {
        if (r.len == 0) continue;
        if (!out.empty() && r.off <= out.back().end())
            out.back().len = std::max(out.back().end(), r.end()) - out.back().off;
        else
            out.push_back(r);
    }
    v = std::move(out);
}

// Appends the parts of [a, a+len) that overlap the sorted, merged ranges `w` to `out`.
void intersect(uint64_t a, uint64_t len, const std::vector<Range>& w, std::vector<Range>& out) {
    uint64_t e = a + len;
    auto it = std::upper_bound(w.begin(), w.end(), a, [](uint64_t v, const Range& r) { return v < r.end(); });
    for (; it != w.end() && it->off < e; ++it) {
        uint64_t s = std::max(a, it->off), t = std::min(e, it->end());
        if (t > s) out.push_back({s, t - s});
    }
}

// Copy of old on-disk bytes [off, off+len) living in the add buffer at `add`.
struct Preserved {
    uint64_t off, len;
    Piece add;
};

// Replaces the parts of Original(cur) pieces that overlap preserved ranges by the Add copies.
bool remap_pieces(std::vector<Piece>& ps, uint32_t cur, const std::vector<Preserved>& map) {
    bool any = false;
    std::vector<Piece> out;
    out.reserve(ps.size());
    for (const Piece& p : ps) {
        if (p.src != Piece::Original || p.chunk != cur) {
            out.push_back(p);
            continue;
        }
        uint64_t a = p.start, e = p.start + p.len;
        auto it = std::upper_bound(map.begin(), map.end(), a,
                                   [](uint64_t v, const Preserved& m) { return v < m.off + m.len; });
        if (it == map.end() || it->off >= e) {
            out.push_back(p);
            continue;
        }
        any = true;
        uint64_t pos = a;
        for (; it != map.end() && it->off < e; ++it) {
            uint64_t s = std::max(pos, it->off), t = std::min(e, it->off + it->len);
            if (s > pos) out.push_back(Piece{Piece::Original, cur, pos, s - pos});
            Piece ap = it->add;
            ap.start += s - it->off;
            ap.len = t - s;
            out.push_back(ap);
            pos = t;
        }
        if (pos < e) out.push_back(Piece{Piece::Original, cur, pos, e - pos});
    }
    if (any) ps = std::move(out);
    return any;
}

bool references_ranges(const std::vector<Piece>& ps, uint32_t cur, const std::vector<Range>& w) {
    std::vector<Range> tmp;
    for (const Piece& p : ps) {
        if (p.src != Piece::Original || p.chunk != cur) continue;
        tmp.clear();
        intersect(p.start, p.len, w, tmp);
        if (!tmp.empty()) return true;
    }
    return false;
}

// Core read loop shared by Document and Snapshot. Starts at piece `i`, `off` bytes into it; the
// caller has already clamped len to the document size. Unreadable bytes are zero-filled (per
// FileSource block, so one bad sector does not blank a whole large read) and reported through
// *ok; *valid (if given, initialised by the caller) is lowered to the index of the first one.
size_t read_pieces(const std::vector<std::shared_ptr<FileSource>>& sources,
                   const std::vector<std::shared_ptr<AddBuffer::Chunk>>& chunks,
                   const std::vector<Piece>& pieces, size_t i, uint64_t off, uint8_t* dst, size_t len,
                   bool* ok, size_t* valid = nullptr, uint8_t* unreadable = nullptr) {
    auto bad_at = [&](size_t at) {
        if (ok) *ok = false;
        if (valid && at < *valid) *valid = at;
    };
    auto mark = [&](size_t at, size_t n) {
        if (unreadable) std::memset(unreadable + at, 1, n);
    };
    size_t done = 0;
    while (done < len && i < pieces.size()) {
        const Piece& p = pieces[i];
        size_t n = size_t(std::min<uint64_t>(p.len - off, len - done));
        if (p.src == Piece::Add) {
            const AddBuffer::Chunk* c = p.chunk < chunks.size() ? chunks[p.chunk].get() : nullptr;
            if (c && p.start + off + n <= c->used) {
                std::memcpy(dst + done, c->data.get() + p.start + off, n);
            } else {
                std::memset(dst + done, 0, n);
                bad_at(done);
                mark(done, n);
            }
        } else {
            const FileSource* s = p.chunk < sources.size() ? sources[p.chunk].get() : nullptr;
            const uint64_t pos = p.start + off;
            size_t got = 0;
            while (got < n) {
                got += s ? s->read(pos + got, dst + done + got, n - got) : 0;
                if (got >= n) break;
                bad_at(done + got);
                // Unreadable: zero-fill up to the next cache block boundary and continue after it.
                uint64_t at = pos + got;
                size_t skip = s ? size_t(std::min<uint64_t>(n - got, FileSource::kBlockSize - at % FileSource::kBlockSize))
                                : n - got;
                std::memset(dst + done + got, 0, skip);
                mark(done + got, skip);
                got += skip;
            }
        }
        done += n;
        ++i;
        off = 0;
    }
    return done;
}

size_t snapshot_read(const Snapshot& s, uint64_t offset, uint8_t* dst, size_t len, bool* ok,
                     size_t* valid = nullptr) {
    if (offset >= s.size_ || len == 0) return 0;
    len = size_t(std::min<uint64_t>(len, s.size_ - offset));
    if (valid) *valid = len;
    auto it = std::upper_bound(s.starts.begin(), s.starts.end(), offset);
    size_t i = size_t(it - s.starts.begin()) - 1;
    return read_pieces(s.sources, s.chunks, s.pieces, i, offset - s.starts[i], dst, len, ok, valid);
}

// Logical size of a piece list.
uint64_t pieces_size(const std::vector<Piece>& ps) {
    uint64_t n = 0;
    for (const Piece& p : ps) n += p.len;
    return n;
}

std::string backup_path_for(const std::string& real) { return real + ".backup"; }

// In-place save: copies `real` to "<real>.backup" through "<real>.backup.tmp" (so an interrupted
// copy never replaces a good backup). Progress counts from 0; cancel aborts cleanly.
bool copy_backup(const std::string& real, Progress* progress, std::string* err) {
    if (progress && progress->cancel) return fail(err, "Save cancelled");
    const std::string bak = backup_path_for(real), tmp = bak + ".tmp";
    auto cb = [&](uint64_t done, uint64_t) {
        if (!progress) return true;
        progress->done = done;
        return !progress->cancel.load();
    };
    std::string e;
    bool cancelled = false;
    if (!os_copy_file(real, tmp, cb, &e, &cancelled)) {
        os_remove(tmp);
        if (cancelled) return fail(err, "Save cancelled");
        return fail(err, "Cannot back up the original to " + bak + " (" + e + "); nothing was changed");
    }
    if (progress && progress->cancel) {  // cancelled during the final flush
        os_remove(tmp);
        return fail(err, "Save cancelled");
    }
    if (!os_replace_file(tmp, bak, &e)) {
        os_remove(tmp);
        return fail(err, "Cannot create " + bak + " (" + e + "); nothing was changed");
    }
    return true;
}

std::string mib(uint64_t n) { return std::to_string((n + (1u << 20) - 1) >> 20) + " MiB"; }

}  // namespace

// ---------------------------------------------------------------------------------------------
// AddBuffer / Snapshot
// ---------------------------------------------------------------------------------------------
Piece AddBuffer::append(const uint8_t* data, size_t len) {
    if (len == 0) return Piece{Piece::Add, 0, 0, 0};
    Chunk* c = chunks_.empty() ? nullptr : chunks_.back().get();
    if (!c || c->capacity - c->used < len) {
        auto nc = std::make_shared<Chunk>();
        nc->capacity = std::max(len, kChunkSize);
        nc->data = std::make_unique_for_overwrite<uint8_t[]>(nc->capacity);
        chunks_.push_back(nc);
        c = nc.get();
    }
    std::memcpy(c->data.get() + c->used, data, len);
    Piece p{Piece::Add, uint32_t(chunks_.size() - 1), c->used, len};
    c->used += len;
    return p;
}

void AddBuffer::push_chunk(const uint8_t* data, size_t len) {
    auto c = std::make_shared<Chunk>();
    if (len) {
        c->data = std::make_unique_for_overwrite<uint8_t[]>(len);
        std::memcpy(c->data.get(), data, len);
    }
    c->capacity = c->used = len;
    chunks_.push_back(std::move(c));
}

const uint8_t* AddBuffer::ptr(uint32_t chunk, uint64_t start) const {
    return chunks_[chunk]->data.get() + start;
}

void AddBuffer::clear() { chunks_.clear(); }

void AddBuffer::release(uint32_t chunk) {
    if (chunk < chunks_.size() && chunks_[chunk]->capacity) chunks_[chunk] = std::make_shared<Chunk>();
}

size_t Snapshot::read(uint64_t offset, uint8_t* dst, size_t len) const {
    return snapshot_read(*this, offset, dst, len, nullptr);
}

size_t Snapshot::read_valid(uint64_t offset, uint8_t* dst, size_t len) const {
    size_t valid = 0;
    snapshot_read(*this, offset, dst, len, nullptr, &valid);
    return valid;
}

// ---------------------------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------------------------
Document::Document() : id_(g_next_doc_id++) { sources_.reserve(16); }
Document::~Document() = default;

std::unique_ptr<Document> Document::open_file(const std::string& path, std::string* err) {
    std::string abs = os_absolute_path(path);
    auto src = FileSource::open(abs, err);
    if (!src) return nullptr;
    std::unique_ptr<Document> d(new Document());
    d->path_ = abs;
    d->sources_.push_back(src);
    d->table_.reset(0, src->size());
    d->disk_stat_ = src->stat_at_open();
    d->state_id_ = d->saved_state_id_ = d->next_state_id_++;
    return d;
}

std::unique_ptr<Document> Document::create_empty(const std::string& display_name) {
    std::unique_ptr<Document> d(new Document());
    d->display_name_ = display_name;
    d->sources_.push_back(nullptr);
    d->state_id_ = d->saved_state_id_ = d->next_state_id_++;
    return d;
}

std::unique_ptr<Document> Document::create_from_bytes(const std::string& display_name,
                                                      const uint8_t* data, size_t len) {
    auto d = create_empty(display_name);
    if (len && data) {
        d->table_.insert(0, d->add_.append(data, len));
        d->base_chunks_ = uint32_t(d->add_.chunks().size());
        d->base_last_used_ = d->add_.chunks().back()->used;
        d->saved_state_id_ = 0;  // never saved anywhere: dirty until saved
    }
    return d;
}

std::string Document::name_locked() const {
    return display_name_.empty() ? path_filename(path_) : display_name_;
}

std::string Document::display_name() const {
    std::lock_guard<std::mutex> lk(mu_);
    return name_locked();
}

const std::shared_ptr<FileSource>& Document::original() const { return sources_.back(); }

// ---------------------------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------------------------
size_t Document::read(uint64_t offset, uint8_t* dst, size_t len) const {
    std::lock_guard<std::mutex> lk(mu_);
    if (offset >= table_.size() || len == 0) return 0;
    len = size_t(std::min<uint64_t>(len, table_.size() - offset));
    auto [i, off] = table_.locate(offset);
    return read_pieces(sources_, add_.chunks(), table_.pieces(), i, off, dst, len, nullptr);
}

size_t Document::read(uint64_t offset, uint8_t* dst, size_t len, uint8_t* unreadable) const {
    std::lock_guard<std::mutex> lk(mu_);
    if (offset >= table_.size() || len == 0) return 0;
    len = size_t(std::min<uint64_t>(len, table_.size() - offset));
    std::memset(unreadable, 0, len);
    auto [i, off] = table_.locate(offset);
    return read_pieces(sources_, add_.chunks(), table_.pieces(), i, off, dst, len, nullptr, nullptr, unreadable);
}

bool Document::io_error() const {
    std::lock_guard<std::mutex> lk(mu_);
    for (const auto& s : sources_)
        if (s && s->io_error()) return true;
    return false;
}

std::shared_ptr<Snapshot> Document::make_snapshot() const {
    auto s = std::make_shared<Snapshot>();
    s->sources = sources_;
    s->pieces = table_.pieces();
    s->starts.resize(s->pieces.size());
    for (size_t i = 0; i < s->pieces.size(); ++i) s->starts[i] = table_.piece_start(i);
    s->chunks = add_.chunks();
    s->size_ = table_.size();
    return s;
}

std::shared_ptr<const Snapshot> Document::snapshot() const {
    std::lock_guard<std::mutex> lk(mu_);
    return make_snapshot();
}

bool Document::is_base_piece(const Piece& p) const {
    if (p.src != Piece::Add || base_chunks_ == 0) return false;
    if (p.chunk + 1 < base_chunks_) return true;
    return p.chunk + 1 == base_chunks_ && p.start + p.len <= base_last_used_;
}

bool Document::is_modified_range(uint64_t offset, uint64_t len) const {
    std::lock_guard<std::mutex> lk(mu_);
    uint64_t size = table_.size();
    if (len == 0 || offset >= size) return false;
    uint64_t end = (len > size - offset) ? size : offset + len;
    bool file_backed = sources_.back() != nullptr;
    uint32_t cur = current_source();
    auto [i, off] = table_.locate(offset);
    (void)off;
    const auto& ps = table_.pieces();
    for (; i < ps.size() && table_.piece_start(i) < end; ++i) {
        const Piece& p = ps[i];
        // Bytes that still come from the file on disk count as unmodified even when an insert or
        // erase before them shifted their offset: only typed / pasted / filled bytes get tinted.
        bool same = file_backed ? (p.src == Piece::Original && p.chunk == cur) : is_base_piece(p);
        if (!same) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------------------------
// Undo bookkeeping
// ---------------------------------------------------------------------------------------------
bool Document::editable() const { return !busy_.load() && !read_only_; }

void Document::set_undo_merge(int ms, uint64_t max_bytes) {
    g_merge_ms = std::max(ms, 0);
    g_merge_max_bytes = max_bytes;
}

void Document::set_clock_for_tests(int64_t (*now_ms)()) { g_clock = now_ms ? now_ms : &steady_ms; }

void Document::set_backup_policy(bool enabled, uint64_t max_bytes) {
    g_backup_enabled = enabled;
    g_backup_max_bytes = max_bytes;
}

UndoEntry Document::capture() const {
    UndoEntry e;
    e.pieces = table_.pieces();
    e.cursor = view_.cursor;
    e.anchor = view_.anchor;
    e.bookmarks = view_.bookmarks;
    e.state_id = state_id_;
    return e;
}

void Document::push_entry(std::vector<UndoEntry>& stack, UndoEntry&& e) {
    stack.push_back(std::move(e));
    if (stack.size() > kMaxUndo) {
        trims_since_reclaim_ += stack.size() - kMaxUndo;
        stack.erase(stack.begin(), stack.begin() + std::ptrdiff_t(stack.size() - kMaxUndo));
    }
}

void Document::push_undo(const char* label, bool coalesce, uint64_t edit_end) {
    push_undo(label, coalesce, edit_end, edit_end);
}

void Document::push_undo(const char* label, bool coalesce, uint64_t edit_begin, uint64_t edit_end) {
    persist_gen_++;
    bool dropped_redo = !redo_.empty();
    redo_.clear();
    // Discarded redo states may have been the last users of an older file version (rewrite save);
    // release it so its disk space is freed. Rare (undo followed by a new edit), so the O(history)
    // scan is fine.
    if (dropped_redo && sources_.size() > 1) prune_sources();
    // Same for add-buffer chunks (undone pastes/fills, history trimmed by kMaxUndo). Here the
    // current state is still in table_ and every other state on a stack, so nothing live is freed.
    if (dropped_redo || trims_since_reclaim_ >= 1000) reclaim_add();
    if (group_depth_ > 0) {
        coalesce_open_ = false;
        if (group_pushed_) return;
        UndoEntry e = capture();
        e.label = group_label_.empty() ? std::string(label) : group_label_;
        push_entry(undo_, std::move(e));
        group_pushed_ = true;
        return;
    }
    const int64_t now = coalesce ? g_clock.load()() : 0;
    if (coalesce && coalesce_open_ && !undo_.empty()) {
        UndoEntry& top = undo_.back();
        const int ms = g_merge_ms.load();
        const uint64_t cap = g_merge_max_bytes.load();
        const bool continues = edit_begin >= top.coalesce_begin && edit_begin <= top.coalesce_end;
        const bool recent = ms <= 0 || now - coalesce_last_ms_ <= ms;
        // A full run only refuses edits that would grow it (the low nibble of its last byte merges).
        const bool full = cap && edit_end > top.coalesce_end && top.coalesce_end - top.coalesce_begin >= cap;
        if (continues && recent && !full) {
            top.coalesce_end = std::max(top.coalesce_end, edit_end);
            coalesce_last_ms_ = now;
            return;
        }
    }
    UndoEntry e = capture();
    e.label = label;
    if (coalesce) {
        e.coalesce_begin = edit_begin;
        e.coalesce_end = edit_end;
        coalesce_last_ms_ = now;
    }
    coalesce_open_ = coalesce;
    push_entry(undo_, std::move(e));
}

void Document::clamp_view() {
    uint64_t n = table_.size();
    if (view_.cursor > n) view_.cursor = n;
    if (view_.anchor > n) view_.anchor = n;
}

void Document::after_change() {
    state_id_ = next_state_id_++;
    generation_++;
    persist_gen_++;
    clamp_view();
}

void Document::apply_entry(const UndoEntry& e) {
    table_.assign(e.pieces);
    view_.cursor = e.cursor;
    view_.anchor = e.anchor;
    view_.bookmarks = e.bookmarks;
    state_id_ = e.state_id;
    generation_++;
    persist_gen_++;
    view_generation++;
    coalesce_open_ = false;
    clamp_view();
}

void Document::apply_pending() {
    if (!pend_) return;
    undo_ = std::move(pend_undo_);
    redo_ = std::move(pend_redo_);
    pend_undo_.clear();
    pend_redo_.clear();
    pend_ = false;
    reclaim_add();  // a save may have dropped history entries (and their pasted bytes)
}

void Document::reclaim_add() {
    trims_since_reclaim_ = 0;
    if (busy_) return;  // a save worker may hold history copies that reference new chunks
    const auto& chunks = add_.chunks();
    std::vector<bool> used(chunks.size(), false);
    auto mark = [&](const std::vector<Piece>& ps) {
        for (const Piece& p : ps)
            if (p.src == Piece::Add && p.chunk < used.size()) used[p.chunk] = true;
    };
    mark(table_.pieces());
    for (const auto* stack : {&undo_, &redo_, &pend_undo_, &pend_redo_})
        for (const UndoEntry& e : *stack) mark(e.pieces);
    for (uint32_t c = 0; c < uint32_t(used.size()); ++c)
        if (!used[c]) add_.release(c);
}

void Document::prune_sources() {
    uint32_t cur = current_source();
    std::vector<bool> used(sources_.size(), false);
    auto mark = [&](const std::vector<Piece>& ps) {
        for (const Piece& p : ps)
            if (p.src == Piece::Original && p.chunk < used.size()) used[p.chunk] = true;
    };
    mark(table_.pieces());
    for (const UndoEntry& e : eff_undo()) mark(e.pieces);
    for (const UndoEntry& e : eff_redo()) mark(e.pieces);
    for (uint32_t i = 0; i < cur; ++i)
        if (!used[i]) sources_[i].reset();
}

// Replaces [pos, pos+del) with `ins` (several pieces in one O(pieces) pass).
void Document::splice(uint64_t pos, uint64_t del, const std::vector<Piece>& ins) {
    if (del) table_.erase(pos, del);
    if (ins.empty()) return;
    if (ins.size() == 1) {
        table_.insert(pos, ins[0]);
        return;
    }
    const auto& ps = table_.pieces();
    std::vector<Piece> out;
    out.reserve(ps.size() + ins.size() + 1);
    if (pos >= table_.size()) {
        out = ps;
        out.insert(out.end(), ins.begin(), ins.end());
    } else {
        auto [i, off] = table_.locate(pos);
        out.insert(out.end(), ps.begin(), ps.begin() + std::ptrdiff_t(i));
        if (off) {
            Piece left = ps[i];
            left.len = off;
            out.push_back(left);
        }
        out.insert(out.end(), ins.begin(), ins.end());
        Piece right = ps[i];
        right.start += off;
        right.len -= off;
        out.push_back(right);
        out.insert(out.end(), ps.begin() + std::ptrdiff_t(i) + 1, ps.end());
    }
    table_.assign(std::move(out));
}

// ---------------------------------------------------------------------------------------------
// Editing
// ---------------------------------------------------------------------------------------------
bool Document::overwrite(uint64_t offset, const uint8_t* data, size_t len, bool coalesce) {
    std::lock_guard<std::mutex> lk(mu_);
    apply_pending();
    if (!editable() || offset > table_.size() || (len && !data)) return false;
    if (len == 0) return true;
    push_undo(coalesce ? "Typing" : "Overwrite", coalesce, offset, offset + len);
    Piece p = add_.append(data, len);
    splice(offset, std::min<uint64_t>(len, table_.size() - offset), {p});
    after_change();
    return true;
}

bool Document::insert(uint64_t offset, const uint8_t* data, size_t len, bool coalesce) {
    std::lock_guard<std::mutex> lk(mu_);
    apply_pending();
    if (!editable() || offset > table_.size() || (len && !data)) return false;
    if (len == 0) return true;
    push_undo(coalesce ? "Typing" : "Insert", coalesce, offset, offset + len);
    Piece p = add_.append(data, len);
    splice(offset, 0, {p});
    after_change();
    return true;
}

bool Document::erase(uint64_t offset, uint64_t len) {
    std::lock_guard<std::mutex> lk(mu_);
    apply_pending();
    if (!editable() || offset >= table_.size() || len == 0) return false;
    len = std::min(len, table_.size() - offset);
    push_undo("Delete", false, offset, offset);
    splice(offset, len, {});
    after_change();
    return true;
}

bool Document::replace(uint64_t offset, uint64_t old_len, const uint8_t* data, size_t len) {
    std::lock_guard<std::mutex> lk(mu_);
    apply_pending();
    if (!editable() || offset > table_.size() || (len && !data)) return false;
    old_len = std::min(old_len, table_.size() - offset);
    if (old_len == 0 && len == 0) return true;
    push_undo("Replace", false, offset, offset + len);
    std::vector<Piece> ins;
    if (len) ins.push_back(add_.append(data, len));
    splice(offset, old_len, ins);
    after_change();
    return true;
}

bool Document::fill(uint64_t offset, uint64_t len, const uint8_t* pattern, size_t pattern_len) {
    std::lock_guard<std::mutex> lk(mu_);
    apply_pending();
    if (!editable() || offset > table_.size() || !pattern || pattern_len == 0) return false;
    if (len == 0) return true;
    if (offset + len < offset) return false;

    // One chunk holding the pattern repeated `unit` bytes (a multiple of the pattern length, so
    // the phase lines up when the chunk range is repeated); pieces then repeat that range.
    uint64_t unit;
    if (len <= AddBuffer::kChunkSize) {
        unit = len;
    } else {
        uint64_t target = std::clamp<uint64_t>(len / 4096, AddBuffer::kChunkSize, kFillMaxUnit);
        unit = std::max<uint64_t>(pattern_len, target / pattern_len * pattern_len);
        unit = std::min(unit, len);
    }
    std::vector<uint8_t> buf(static_cast<size_t>(unit));
    for (size_t i = 0; i < buf.size(); ++i) buf[i] = pattern[i % pattern_len];

    push_undo("Fill", false, offset, offset + len);
    Piece p = add_.append(buf.data(), buf.size());
    std::vector<Piece> ins(size_t(len / unit), p);
    if (len % unit) {
        Piece tail = p;
        tail.len = len % unit;
        ins.push_back(tail);
    }
    splice(offset, std::min(len, table_.size() - offset), ins);
    after_change();
    return true;
}

void Document::begin_group(const std::string& label) {
    std::lock_guard<std::mutex> lk(mu_);
    if (group_depth_ == 0) {
        group_label_ = label;
        group_pushed_ = false;
        coalesce_open_ = false;
    } else if (!label.empty()) {
        // Innermost non-empty label wins, also for the step an outer group already pushed.
        group_label_ = label;
        if (group_pushed_ && !undo_.empty()) undo_.back().label = label;
    }
    group_depth_++;
}

bool Document::in_group() const {
    std::lock_guard<std::mutex> lk(mu_);
    return group_depth_ > 0;
}

void Document::end_group() {
    std::lock_guard<std::mutex> lk(mu_);
    if (group_depth_ == 0) return;
    if (--group_depth_ == 0) {
        group_pushed_ = false;
        coalesce_open_ = false;
    }
}

bool Document::add_bookmark(const Bookmark& b) {
    std::lock_guard<std::mutex> lk(mu_);
    apply_pending();
    if (busy_) return false;
    push_undo("Add bookmark", false, 0, 0);
    view_.bookmarks.push_back(b);
    view_generation++;
    return true;
}

bool Document::remove_bookmark(size_t index) {
    std::lock_guard<std::mutex> lk(mu_);
    apply_pending();
    if (busy_ || index >= view_.bookmarks.size()) return false;
    push_undo("Remove bookmark", false, 0, 0);
    view_.bookmarks.erase(view_.bookmarks.begin() + std::ptrdiff_t(index));
    view_generation++;
    return true;
}

bool Document::update_bookmark(size_t index, const Bookmark& b) {
    std::lock_guard<std::mutex> lk(mu_);
    apply_pending();
    if (busy_ || index >= view_.bookmarks.size()) return false;
    push_undo("Edit bookmark", false, 0, 0);
    view_.bookmarks[index] = b;
    view_generation++;
    return true;
}

bool Document::can_undo() const {
    std::lock_guard<std::mutex> lk(mu_);
    return !busy_ && !read_only_ && group_depth_ == 0 && !eff_undo().empty();
}

bool Document::can_redo() const {
    std::lock_guard<std::mutex> lk(mu_);
    return !busy_ && !read_only_ && group_depth_ == 0 && !eff_redo().empty();
}

bool Document::undo() {
    std::lock_guard<std::mutex> lk(mu_);
    apply_pending();
    if (!editable() || group_depth_ > 0 || undo_.empty()) return false;
    UndoEntry target = std::move(undo_.back());
    undo_.pop_back();
    UndoEntry now = capture();
    now.label = target.label;
    push_entry(redo_, std::move(now));
    apply_entry(target);
    return true;
}

bool Document::redo() {
    std::lock_guard<std::mutex> lk(mu_);
    apply_pending();
    if (!editable() || group_depth_ > 0 || redo_.empty()) return false;
    UndoEntry target = std::move(redo_.back());
    redo_.pop_back();
    UndoEntry now = capture();
    now.label = target.label;
    push_entry(undo_, std::move(now));
    apply_entry(target);
    return true;
}

bool Document::dirty() const {
    std::lock_guard<std::mutex> lk(mu_);
    return state_id_ != saved_state_id_;
}

// ---------------------------------------------------------------------------------------------
// Saving
// ---------------------------------------------------------------------------------------------
bool Document::save(Progress* progress, std::string* err, bool force) {
    bool expected = false;
    if (!busy_.compare_exchange_strong(expected, true)) return fail(err, "A save is already in progress");
    BusyGuard guard{busy_};

    std::unique_lock<std::mutex> lk(mu_);
    last_save_ = {};
    if (path_.empty()) return fail(err, "Untitled document: use Save As");
    if (read_only_) return fail(err, "Document is read-only");
    if (progress) {
        progress->done = 0;
        progress->total = 0;
    }
    if (state_id_ == saved_state_id_) return true;  // nothing to write
    std::string path = path_;
    std::shared_ptr<FileSource> src = sources_.back();
    uint32_t cur = current_source();
    FileStat known = disk_stat_;
    auto snap = make_snapshot();
    bool inplace = src && table_.is_inplace_compatible(cur, src->size());
    const std::string name = name_locked();
    lk.unlock();

    if (known.is_device || (src && src->stat_at_open().is_device)) {
        // Devices have no meaningful size/mtime and cannot be replaced by a rewritten copy.
        if (!inplace)
            return fail(err, "Size-changing edits cannot be saved to a device (" + name +
                                 "); only overwrites can. Use Save As to write an image file.");
        return save_inplace(path, src, cur, *snap, progress, err);
    }
    FileStat now = os_stat(path);
    // Replaced by another file (atomic save of another program): our handle still reads the version
    // our pieces refer to, so the rewrite path produces exactly what the user sees.
    const bool replaced = os_identity_differs(now, known);
    const bool modified = src && now.exists && !replaced && (now.size != known.size || now.mtime_ns != known.mtime_ns);
    if (modified) {
        if (!force)
            return fail(err, name + " was modified on disk by another program since it was opened; save aborted "
                                    "(the result would mix both versions). Reload it, or use Save As.");
        src->invalidate();  // forced: at least consistent with what is on disk now
    }
    // Only patch in place when the file is still exactly the version our pieces refer to.
    inplace = inplace && now.exists && !replaced && !modified && now.size == src->size();
    return inplace ? save_inplace(path, src, cur, *snap, progress, err)
                   : save_rewrite(path, true, *snap, progress, err);
}

SaveInfo Document::last_save_info() const {
    std::lock_guard<std::mutex> lk(mu_);
    return last_save_;
}

bool Document::need_backup_locked(const std::string& real, const FileStat& st, bool copy) {
    if (!g_backup_enabled.load() || !st.exists || st.is_dir) return false;
    if (std::find(backup_done_.begin(), backup_done_.end(), real) != backup_done_.end()) return false;
    const uint64_t limit = g_backup_max_bytes.load();
    std::string why;
    if (st.is_device)
        why = "No backup is made when saving to a device.";
    else if (copy && limit && st.size > limit)
        why = "No backup made: " + path_filename(real) + " (" + mib(st.size) + ") is larger than the backup size limit (" +
              mib(limit) + ").";
    if (why.empty()) return true;
    backup_done_locked(real);  // reported once; later saves would not back up the original anyway
    last_save_.backup_skipped = true;
    last_save_.note = why;
    return false;
}

void Document::backup_done_locked(const std::string& real) {
    if (std::find(backup_done_.begin(), backup_done_.end(), real) == backup_done_.end()) backup_done_.push_back(real);
}

bool Document::save_as(const std::string& path, Progress* progress, std::string* err) {
    std::string target = os_absolute_path(path);
    if (target.empty()) return fail(err, "No file name given");
    bool same;
    {
        std::lock_guard<std::mutex> lk(mu_);
        same = !path_.empty() && (path_ == target || os_same_file(path_, target));
    }
    if (same) return save(progress, err, true);  // explicitly chosen to overwrite this file
    if (os_stat(target).is_device)
        return fail(err, "Cannot Save As onto a device; open the device and overwrite bytes instead");

    bool expected = false;
    if (!busy_.compare_exchange_strong(expected, true)) return fail(err, "A save is already in progress");
    BusyGuard guard{busy_};
    std::shared_ptr<Snapshot> snap;
    {
        std::lock_guard<std::mutex> lk(mu_);
        last_save_ = {};
        snap = make_snapshot();
    }
    if (progress) {
        progress->done = 0;
        progress->total = 0;
    }
    return save_rewrite(target, false, *snap, progress, err);
}

// In-place: pieces are size-preserving with every Original byte at its own offset, so only the
// Add pieces need writing. Old bytes still referenced by history are copied first (see header).
bool Document::save_inplace(const std::string& path, const std::shared_ptr<FileSource>& src, uint32_t cur,
                            const Snapshot& snap, Progress* progress, std::string* err) {
    std::vector<Range> w;  // file ranges that will be overwritten
    for (size_t i = 0; i < snap.pieces.size(); ++i)
        if (snap.pieces[i].src == Piece::Add) w.push_back({snap.starts[i], snap.pieces[i].len});
    merge_ranges(w);

    // History states are only touched by this thread while busy, so copies are consistent.
    std::vector<UndoEntry> undo, redo;
    {
        std::lock_guard<std::mutex> lk(mu_);
        undo = eff_undo();
        redo = eff_redo();
    }
    std::vector<Range> need;
    for (const auto* stack : {&undo, &redo})
        for (const UndoEntry& u : *stack)
            for (const Piece& p : u.pieces)
                if (p.src == Piece::Original && p.chunk == cur) intersect(p.start, p.len, w, need);
    merge_ranges(need);
    uint64_t need_bytes = 0, write_bytes = 0;
    for (const Range& r : need) need_bytes += r.len;
    for (const Range& r : w) write_bytes += r.len;
    bool trim = need_bytes > kMaxPreserve;

    const std::string real = os_resolve_symlinks(path);
    FileStat disk = os_stat(path);
    if (src->stat_at_open().is_device) disk.is_device = true;
    bool backup;
    {
        std::lock_guard<std::mutex> lk(mu_);
        backup = need_backup_locked(real, disk, true);
    }
    const uint64_t backup_bytes = backup ? disk.size : 0;
    if (progress) progress->total = backup_bytes + (trim ? 0 : need_bytes) + write_bytes;
    // Before opening the file for writing (CopyFileExW does not share it with a writer).
    if (backup) {
        if (!copy_backup(real, progress, err)) return false;
        if (progress) progress->done = backup_bytes;
        std::lock_guard<std::mutex> lk(mu_);
        backup_done_locked(real);
        last_save_.backup_created = true;
        last_save_.backup_path = backup_path_for(real);
    }

    std::string e;
    auto out = OsFile::open(path, OsFile::Mode::ReadWrite, &e);
    if (!out) return fail(err, "Cannot open " + path + " for writing: " + e);
    if (out->size() != src->size()) return fail(err, "File size changed on disk; save aborted");

    bool history_changed = false;
    if (!trim) {
        std::vector<Preserved> map;
        std::vector<uint8_t> buf(kPreserveBlock);
        uint64_t done = backup_bytes;
        for (const Range& r : need) {
            for (uint64_t o = r.off; o < r.end();) {
                if (progress && progress->cancel) return fail(err, "Save cancelled");
                size_t n = size_t(std::min<uint64_t>(kPreserveBlock, r.end() - o));
                if (src->read(o, buf.data(), n) != n)
                    return fail(err, "Cannot read the original bytes of " + path + "; save aborted");
                Piece p;
                {
                    std::lock_guard<std::mutex> lk(mu_);  // readers walk add_ chunks under mu_
                    p = add_.append(buf.data(), n);
                }
                map.push_back({o, n, p});
                o += n;
                done += n;
                if (progress) progress->done = done;
            }
        }
        for (auto* stack : {&undo, &redo})
            for (UndoEntry& u : *stack) history_changed |= remap_pieces(u.pieces, cur, map);
    } else {
        if (progress && progress->cancel) return fail(err, "Save cancelled");
        for (auto* stack : {&undo, &redo}) {
            size_t before = stack->size();
            stack->erase(std::remove_if(stack->begin(), stack->end(),
                                        [&](const UndoEntry& u) { return references_ranges(u.pieces, cur, w); }),
                         stack->end());
            history_changed |= stack->size() != before;
        }
    }
    // Commit the rewritten history BEFORE touching the file: it is valid either way (the copies
    // equal the current disk bytes), so a failed write below cannot corrupt undo.
    if (history_changed) {
        std::lock_guard<std::mutex> lk(mu_);
        pend_undo_ = std::move(undo);
        pend_redo_ = std::move(redo);
        pend_ = true;
        persist_gen_++;
    }

    // Point of no return: the file is being patched; cancel is no longer checked.
    CommitGuard commit{progress};
    commit.begin();
    bool ok = true;
    uint64_t done = progress ? progress->done.load() : 0;
    for (size_t i = 0; i < snap.pieces.size() && ok; ++i) {
        const Piece& p = snap.pieces[i];
        if (p.src != Piece::Add) continue;
        const uint8_t* data = snap.chunks[p.chunk]->data.get() + p.start;
        for (uint64_t o = 0; o < p.len;) {
            size_t n = size_t(std::min<uint64_t>(kSaveBlock, p.len - o));
            if (!out->write_at(snap.starts[i] + o, data + o, n)) {
                ok = false;
                break;
            }
            o += n;
            done += n;
            if (progress) progress->done = done;
        }
    }
    if (ok) ok = out->flush();
    out.reset();
    src->invalidate();
    if (!ok)
        return fail(err, "Write error while saving " + path +
                             " in place; the file may be partially written. Your edits are still in the "
                             "document - try Save As.");

    FileStat st = os_stat(path);
    {
        std::lock_guard<std::mutex> lk(mu_);
        table_.reset(cur, src->size());
        saved_state_id_ = state_id_;
        disk_stat_ = st;
        coalesce_open_ = false;
        persist_gen_++;
    }
    if (trim && err)
        *err = "Saved. Undo history that referenced the overwritten bytes was dropped (too large to keep).";
    return true;
}

// Rewrite: stream everything to "<target>.hexer-tmp", then atomically replace the target.
bool Document::save_rewrite(const std::string& target, bool same_file, const Snapshot& snap,
                            Progress* progress, std::string* err) {
    // Write the file a symlink points to instead of replacing the link by a regular file.
    const std::string real = os_resolve_symlinks(target);
    const std::string tmp = real + ".hexer-tmp";
    {
        std::string e;
        auto f = OsFile::open(tmp, OsFile::Mode::CreateTruncate, &e);
        if (!f) return fail(err, "Cannot create " + tmp + ": " + e);
        uint64_t size = snap.size();
        if (progress) progress->total = size;
        std::vector<uint8_t> buf(size_t(std::min<uint64_t>(kSaveBlock, std::max<uint64_t>(size, 1))));
        std::string why;
        for (uint64_t off = 0; off < size;) {
            if (progress && progress->cancel) {
                why = "Save cancelled";
                break;
            }
            size_t n = size_t(std::min<uint64_t>(buf.size(), size - off));
            bool rok = true;
            if (snapshot_read(snap, off, buf.data(), n, &rok) != n || !rok) {
                why = "Read error while saving (a source file is unreadable); nothing was changed";
                break;
            }
            if (!f->write_at(off, buf.data(), n)) {
                why = "Write error while saving (disk full?); nothing was changed";
                break;
            }
            off += n;
            if (progress) progress->done = off;
        }
        if (why.empty() && !f->flush()) why = "Flush failed while saving; nothing was changed";
        // Flushing gigabytes takes a while: Cancel pressed meanwhile still stops before the rename.
        if (why.empty() && progress && progress->cancel) why = "Save cancelled";
        f.reset();
        if (!why.empty()) {
            os_remove(tmp);
            return fail(err, why);
        }
    }
    const FileStat real_st = os_stat(real);
    if (real_st.exists) os_copy_permissions(real, tmp);

    std::shared_ptr<FileSource> old_cur;
    bool backup;
    {
        std::lock_guard<std::mutex> lk(mu_);
        old_cur = sources_.back();
        backup = need_backup_locked(real, real_st, false);
    }
    // Point of no return: the rename replaces the target; cancel is no longer checked.
    CommitGuard commit{progress};
    commit.begin();
    std::string rerr;
    const std::string bak = backup_path_for(real);
    bool replaced = false;
    if (backup) {
        // Keep the previous version as .backup. Preferred: give it that second name (hard link,
        // atomically replacing an older .backup); the replace below then swaps the target in one
        // step, so it is never missing. Without hard links (FAT, some shares): rename it away
        // first, then move the new file into place (rolled back if that fails).
        const std::string link = bak + ".tmp";
        os_remove(link);
        if (!(os_hard_link(real, link) && os_replace_file(link, bak))) {
            os_remove(link);
            if (!os_replace_file(real, bak, &rerr)) {
                os_remove(tmp);
                return fail(err, "Cannot keep the original as " + bak + " (" + rerr +
                                     "); nothing was changed. Turn off backups in Settings to save without one.");
            }
            if (!os_replace_file(tmp, real, &rerr)) {
                std::string e2;
                const bool restored = os_replace_file(bak, real, &e2);
                if (restored) os_remove(tmp);
                return fail(err, "Cannot replace " + target + ": " + rerr +
                                     (restored ? std::string("; nothing was changed")
                                               : "; the original is now " + bak + " and the new contents " + tmp));
            }
            replaced = true;
        }
    }
    if (!replaced && !os_replace_file(tmp, real, &rerr)) {
        // Some filesystems cannot replace a file we still hold open: release ours and retry.
        bool ok = false;
        if (same_file && old_cur) {
            old_cur->close_file();
            ok = os_replace_file(tmp, real, &rerr);
            if (!ok) old_cur->reopen_file(nullptr);
        }
        if (!ok) {
            os_remove(tmp);
            return fail(err, "Cannot replace " + target + ": " + rerr);
        }
    }
    if (backup) {
        std::lock_guard<std::mutex> lk(mu_);
        backup_done_locked(real);
        last_save_.backup_created = true;
        last_save_.backup_path = bak;
    }
    if (!real_st.exists) {
        std::lock_guard<std::mutex> lk(mu_);
        backup_done_locked(real);  // we created this file: there is no original to keep
    }

    std::string oerr;
    auto ns = FileSource::open(target, &oerr);
    if (!ns) return fail(err, "Saved, but the file could not be reopened: " + oerr);
    if (ns->size() != snap.size())
        return fail(err, "Saved, but the file on disk has an unexpected size (modified by another program?)");

    // Old versions must stay readable for history. Probe each one past its cache.
    std::vector<std::shared_ptr<FileSource>> olds;
    {
        std::lock_guard<std::mutex> lk(mu_);
        olds = sources_;
    }
    std::vector<bool> bad(olds.size(), false);
    bool any_bad = false;
    for (size_t i = 0; i < olds.size(); ++i) {
        if (!olds[i] || olds[i]->size() == 0) continue;
        olds[i]->invalidate();
        uint8_t b;
        if (olds[i]->read(0, &b, 1) != 1) bad[i] = any_bad = true;
    }

    {
        std::lock_guard<std::mutex> lk(mu_);
        sources_.push_back(ns);
        uint32_t cur = current_source();
        table_.reset(cur, ns->size());
        if (!same_file) {
            path_ = target;
            display_name_.clear();
        }
        saved_state_id_ = state_id_;
        disk_stat_ = ns->stat_at_open();
        coalesce_open_ = false;
        persist_gen_++;
        if (any_bad) {
            auto refs_bad = [&](const UndoEntry& u) {
                for (const Piece& p : u.pieces)
                    if (p.src == Piece::Original && p.chunk < bad.size() && bad[p.chunk]) return true;
                return false;
            };
            std::vector<UndoEntry> undo = eff_undo(), redo = eff_redo();
            undo.erase(std::remove_if(undo.begin(), undo.end(), refs_bad), undo.end());
            redo.erase(std::remove_if(redo.begin(), redo.end(), refs_bad), redo.end());
            pend_undo_ = std::move(undo);
            pend_redo_ = std::move(redo);
            pend_ = true;
        }
        prune_sources();
    }
    if (any_bad && err)
        *err = "Saved. The previous file version could not be kept open, so undo history from before "
               "this save was dropped.";
    return true;
}

// ---------------------------------------------------------------------------------------------
// External changes
// ---------------------------------------------------------------------------------------------
bool Document::changed_on_disk() const {
    std::string path;
    FileStat known;
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (busy_ || path_.empty() || !sources_.back()) return false;
        path = path_;
        known = disk_stat_;
    }
    if (known.is_device) return false;  // no meaningful size/mtime
    FileStat now = os_stat(path);
    return !now.exists || now.size != known.size || now.mtime_ns != known.mtime_ns ||
           os_identity_differs(now, known);
}

FileStat Document::disk_stat() const {
    std::lock_guard<std::mutex> lk(mu_);
    return disk_stat_;
}

bool Document::reload(std::string* err) {
    std::lock_guard<std::mutex> lk(mu_);
    apply_pending();
    if (busy_) return fail(err, "A save is in progress");
    if (path_.empty()) return fail(err, "Untitled document has no file to reload");
    auto src = FileSource::open(path_, err);
    if (!src) return false;
    sources_.clear();
    sources_.push_back(src);
    add_.clear();
    table_.reset(0, src->size());
    undo_.clear();
    redo_.clear();
    group_depth_ = 0;
    group_pushed_ = false;
    coalesce_open_ = false;
    base_chunks_ = 0;
    disk_stat_ = src->stat_at_open();
    state_id_ = saved_state_id_ = next_state_id_++;
    generation_++;
    persist_gen_++;
    view_generation++;
    clamp_view();
    return true;
}

// ---------------------------------------------------------------------------------------------
// Session support
// ---------------------------------------------------------------------------------------------
PersistedDoc Document::persist() const {
    std::lock_guard<std::mutex> lk(mu_);
    PersistedDoc d;
    d.path = path_;
    d.display_name = name_locked();
    d.file_stat = disk_stat_;
    d.view = view_;
    d.read_only = read_only_;
    d.dirty = state_id_ != saved_state_id_;
    d.backup_done = backup_done_;

    const uint32_t cur = current_source();
    const bool has_src = sources_.back() != nullptr;
    const auto& chunks = add_.chunks();
    auto usable = [&](const std::vector<Piece>& ps) {
        for (const Piece& p : ps)
            if (p.src == Piece::Original && (!has_src || p.chunk != cur)) return false;
        return true;
    };
    auto renumber = [](std::vector<Piece> ps) {
        for (Piece& p : ps)
            if (p.src == Piece::Original) p.chunk = 0;
        return ps;
    };
    // The saved state is exported as id 1 (restore() relies on that); others shift by one.
    auto map_id = [&](uint64_t id) { return id == saved_state_id_ ? uint64_t(1) : id + 1; };

    std::vector<std::vector<uint8_t>> extra;  // inlined bytes of older file versions
    if (usable(table_.pieces())) {
        d.pieces = renumber(table_.pieces());
    } else {
        uint64_t old_bytes = 0;
        for (const Piece& p : table_.pieces())
            if (p.src == Piece::Original && p.chunk != cur) old_bytes += p.len;
        if (old_bytes <= kMaxMaterialize) {
            for (const Piece& p : table_.pieces()) {
                if (p.src == Piece::Original && p.chunk != cur) {
                    std::vector<uint8_t> bytes(size_t(p.len), 0);
                    const FileSource* s = p.chunk < sources_.size() ? sources_[p.chunk].get() : nullptr;
                    if (s) s->read(p.start, bytes.data(), bytes.size());
                    d.pieces.push_back(Piece{Piece::Add, uint32_t(chunks.size() + extra.size()), 0, p.len});
                    extra.push_back(std::move(bytes));
                } else {
                    Piece q = p;
                    if (q.src == Piece::Original) q.chunk = 0;
                    d.pieces.push_back(q);
                }
            }
        } else {
            // Too large to inline: fall back to the last saved state of the current version.
            // The session warns about this on restore; hot_exit_safe() lets the UI ask first.
            if (has_src && sources_.back()->size())
                d.pieces.push_back(Piece{Piece::Original, 0, 0, sources_.back()->size()});
            d.dirty = false;
            d.edits_dropped = true;
        }
    }
    for (const UndoEntry& u : eff_undo())
        if (usable(u.pieces)) {
            UndoEntry c = u;
            c.pieces = renumber(u.pieces);
            c.state_id = map_id(u.state_id);
            d.undo.push_back(std::move(c));
        }
    for (const UndoEntry& u : eff_redo())
        if (usable(u.pieces)) {
            UndoEntry c = u;
            c.pieces = renumber(u.pieces);
            c.state_id = map_id(u.state_id);
            d.redo.push_back(std::move(c));
        }

    // Export only the referenced prefix of each add chunk (old typing garbage stays behind).
    std::vector<uint64_t> need(chunks.size(), 0);
    auto mark = [&](const std::vector<Piece>& ps) {
        for (const Piece& p : ps)
            if (p.src == Piece::Add && p.chunk < need.size()) need[p.chunk] = std::max(need[p.chunk], p.start + p.len);
    };
    mark(d.pieces);
    for (const UndoEntry& u : d.undo) mark(u.pieces);
    for (const UndoEntry& u : d.redo) mark(u.pieces);
    d.add_chunks.resize(chunks.size() + extra.size());
    for (size_t c = 0; c < chunks.size(); ++c) {
        uint64_t n = std::min<uint64_t>(need[c], chunks[c]->used);
        if (n) d.add_chunks[c].assign(chunks[c]->data.get(), chunks[c]->data.get() + n);
    }
    for (size_t k = 0; k < extra.size(); ++k) d.add_chunks[chunks.size() + k] = std::move(extra[k]);
    return d;
}

bool Document::hot_exit_safe() const {
    std::lock_guard<std::mutex> lk(mu_);
    if (state_id_ == saved_state_id_) return true;
    const uint32_t cur = current_source();
    uint64_t old_bytes = 0;
    for (const Piece& p : table_.pieces())
        if (p.src == Piece::Original && p.chunk != cur) old_bytes += p.len;
    return old_bytes <= kMaxMaterialize;
}

std::unique_ptr<Document> Document::restore(const PersistedDoc& st, bool* changed_on_disk, std::string* err,
                                            std::string* note) {
    if (changed_on_disk) *changed_on_disk = false;
    std::unique_ptr<Document> d(new Document());
    d->path_ = st.path;
    d->display_name_ = st.path.empty() ? st.display_name : std::string();
    d->read_only_ = st.read_only;
    d->view_ = st.view;
    d->backup_done_ = st.backup_done;
    for (const auto& c : st.add_chunks) d->add_.push_chunk(c.data(), c.size());

    bool has_original = false;
    for (const Piece& p : st.pieces) has_original |= p.src == Piece::Original;

    bool file_changed = false;
    bool recovered = false;
    std::shared_ptr<FileSource> src;
    if (!st.path.empty()) {
        std::string e;
        src = FileSource::open(st.path, &e);
        if (!src) {
            if (has_original) {
                fail(err, path_filename(st.path) + " could not be opened (" + e + ")");
                return nullptr;
            }
            // The document no longer depends on the file: keep the edits as an untitled doc.
            recovered = true;
            d->path_.clear();
            d->display_name_ = (st.display_name.empty() ? path_filename(st.path) : st.display_name) + " (recovered)";
        } else {
            FileStat now = src->stat_at_open();
            file_changed = !now.is_device && (now.size != st.file_stat.size || now.mtime_ns != st.file_stat.mtime_ns);
            d->disk_stat_ = now;
        }
    }
    d->sources_.push_back(src);
    const uint64_t src_size = src ? src->size() : 0;
    const auto& chunks = d->add_.chunks();

    // Validates a stored piece list; Original pieces are clamped to the (possibly changed) file.
    auto fix = [&](const std::vector<Piece>& in, std::vector<Piece>& out) {
        out.clear();
        for (const Piece& p : in) {
            if (p.len == 0) continue;
            if (p.src == Piece::Add) {
                if (p.chunk >= chunks.size()) return false;
                uint64_t used = chunks[p.chunk]->used;
                if (p.start > used || p.len > used - p.start) return false;
                out.push_back(p);
            } else if (p.src == Piece::Original) {
                if (!src) return false;
                if (p.start >= src_size) continue;
                Piece q = p;
                q.chunk = 0;
                q.len = std::min(q.len, src_size - q.start);
                out.push_back(q);
            } else {
                return false;
            }
        }
        return true;
    };

    // Our own save already wrote this exact content (the process ended before the session was
    // rewritten): replaying the pieces on top of it would corrupt it. Size plus every added byte
    // (up to a budget) at its offset must match; Original bytes cannot be checked (old version).
    bool already_saved = false;
    if (file_changed && st.dirty && src && pieces_size(st.pieces) == src_size) {
        already_saved = true;
        uint64_t at = 0, budget = 64ull << 20;
        std::vector<uint8_t> buf;
        for (const Piece& p : st.pieces) {
            if (p.src == Piece::Add && budget) {
                if (p.chunk >= chunks.size() || p.start > chunks[p.chunk]->used ||
                    p.len > chunks[p.chunk]->used - p.start) {
                    already_saved = false;
                    break;
                }
                size_t n = size_t(std::min(p.len, budget));
                buf.resize(n);
                if (src->read(at, buf.data(), n) != n ||
                    std::memcmp(buf.data(), chunks[p.chunk]->data.get() + p.start, n) != 0) {
                    already_saved = false;
                    break;
                }
                budget -= n;
            }
            at += p.len;
        }
        if (already_saved && note)
            *note = (st.display_name.empty() ? path_filename(st.path) : st.display_name) +
                    " was saved just before the last session ended; it was opened from disk and undo history "
                    "from before that save was dropped";
    }

    const bool clean_but_changed = file_changed && (!st.dirty || already_saved);
    if (clean_but_changed) {
        d->table_.reset(0, src_size);  // nothing of ours to keep: show the new contents
    } else {
        std::vector<Piece> ps;
        if (!fix(st.pieces, ps)) {
            fail(err, "Session data for " + (st.display_name.empty() ? st.path : st.display_name) + " is corrupt");
            return nullptr;
        }
        d->table_.assign(std::move(ps));
    }

    uint64_t max_id = 1;
    auto load_stack = [&](const std::vector<UndoEntry>& in, std::vector<UndoEntry>& out) {
        for (const UndoEntry& e : in) {
            UndoEntry u = e;
            if (!fix(e.pieces, u.pieces)) continue;
            max_id = std::max(max_id, u.state_id);
            out.push_back(std::move(u));
        }
        if (out.size() > kMaxUndo) out.erase(out.begin(), out.begin() + std::ptrdiff_t(out.size() - kMaxUndo));
    };
    if (!clean_but_changed) {
        load_stack(st.undo, d->undo_);
        load_stack(st.redo, d->redo_);
    }

    if ((!st.dirty || already_saved) && !recovered) {
        d->state_id_ = d->saved_state_id_ = 1;
    } else {
        d->state_id_ = max_id + 1;
        d->saved_state_id_ = (file_changed || recovered) ? 0 : 1;
    }
    d->next_state_id_ = std::max(max_id, d->state_id_) + 1;

    if (!src) {
        d->base_chunks_ = uint32_t(chunks.size());
        d->base_last_used_ = chunks.empty() ? 0 : chunks.back()->used;
    }
    d->clamp_view();
    if (changed_on_disk) *changed_on_disk = file_changed && !already_saved;
    return d;
}

}  // namespace hx
