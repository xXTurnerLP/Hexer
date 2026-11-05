#pragma once
// A Document = original file (streamed, never fully loaded) + piece table of edits + undo history
// + per-document view state. Edits cost O(pieces), never O(file size).
//
// Threading model:
//   * The UI thread owns the Document and is the only one that mutates it.
//   * Background readers (search, hashing, ...) take a Snapshot: an immutable, cheap copy of the
//     piece list that shares the FileSource and add-buffer chunks via shared_ptr.
//   * save()/save_as() may run on a worker thread; while busy() is true the UI must not mutate
//     the document (every mutating call returns false / no-ops while busy).
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "core/file_source.h"
#include "core/os_file.h"
#include "core/piece_table.h"

namespace hx {

// Append-only chunked buffer holding every inserted/overwritten byte. Chunk memory never moves and
// bytes are never modified once written, so Snapshots can read it from other threads.
class AddBuffer {
public:
    static constexpr size_t kChunkSize = 1 << 20;  // 1 MiB; larger single appends get their own chunk
    struct Chunk {
        std::unique_ptr<uint8_t[]> data;
        size_t capacity = 0;
        size_t used = 0;
    };
    // Appends and returns a Piece{Add, chunk, start, len} describing the bytes. len must be > 0.
    Piece append(const uint8_t* data, size_t len);
    const uint8_t* ptr(uint32_t chunk, uint64_t start) const;
    // Appends a new chunk holding exactly these bytes (session restore keeps chunk indices stable).
    void push_chunk(const uint8_t* data, size_t len);
    const std::vector<std::shared_ptr<Chunk>>& chunks() const { return chunks_; }
    void clear();
    // Frees a chunk nothing references any more (its index stays valid but empty; Snapshots that
    // still hold the old chunk keep their copy alive).
    void release(uint32_t chunk);

private:
    std::vector<std::shared_ptr<Chunk>> chunks_;
};

// Immutable point-in-time view of a document's bytes, safe to read from any thread.
class Snapshot {
public:
    uint64_t size() const { return size_; }
    size_t read(uint64_t offset, uint8_t* dst, size_t len) const;  // returns bytes copied
    // Like read() (unreadable bytes are zero-filled), but returns only how many bytes before the
    // first unreadable one (I/O error) are valid.
    size_t read_valid(uint64_t offset, uint8_t* dst, size_t len) const;

    // Implementation detail, public for Document/Session code.
    std::vector<std::shared_ptr<FileSource>> sources;      // file versions (Original piece .chunk)
    std::vector<Piece> pieces;
    std::vector<uint64_t> starts;                          // logical start of each piece
    std::vector<std::shared_ptr<AddBuffer::Chunk>> chunks;
    uint64_t size_ = 0;
};

struct Bookmark {
    uint64_t offset = 0;
    uint64_t length = 1;
    std::string name;
    uint32_t color = 0;  // 0 = default
    std::string note;    // free text shown in the Bookmarks panel ("" = none)
};

// Per-document UI state; persisted by the session so tabs reopen exactly where you left them.
// Selection model: half-open [min(anchor, cursor), max(anchor, cursor)); empty when equal.
struct ViewState {
    uint64_t cursor = 0;
    uint64_t anchor = 0;
    bool low_nibble = false;   // next hex digit typed goes to the low nibble of the cursor byte
    bool ascii_focus = false;  // caret is in the text column
    uint64_t top_row = 0;      // first visible row
    std::string parser;        // forced parser name; "" = auto-detect
    std::vector<Bookmark> bookmarks;

    uint64_t sel_begin() const { return anchor < cursor ? anchor : cursor; }
    uint64_t sel_end() const { return anchor < cursor ? cursor : anchor; }
    uint64_t sel_len() const { return sel_end() - sel_begin(); }
    bool has_selection() const { return anchor != cursor; }
};

// One undo/redo step: the full piece list + cursor/selection/bookmarks *before* (undo stack) or
// *after* (redo stack) an action. Piece lists are small (they describe edits, not data).
struct UndoEntry {
    std::vector<Piece> pieces;
    uint64_t cursor = 0, anchor = 0;
    std::vector<Bookmark> bookmarks;
    uint64_t state_id = 0;
    // Typing-run coalescing: an edit with coalesce=true merges into this entry when it is still the
    // top of the undo stack, nothing else happened since, and the edit starts inside
    // [coalesce_begin, coalesce_end] (so "insert nibble, then overwrite same byte" is one step),
    // within the time / size limits of Document::set_undo_merge().
    uint64_t coalesce_begin = UINT64_MAX;
    uint64_t coalesce_end = UINT64_MAX;
    std::string label;                   // "Typing", "Paste", "Fill", "Add bookmark", "Script: ..."
};

// Everything needed to rebuild a document after a restart (hot exit), including its undo history.
struct PersistedDoc {
    std::string path;                    // "" = untitled
    std::string display_name;
    FileStat file_stat;                  // stat of the file version the pieces refer to
    std::vector<Piece> pieces;           // Original pieces: chunk == 0 (= the file at `path`)
    std::vector<std::vector<uint8_t>> add_chunks;  // used bytes of every add chunk, by index
    std::vector<UndoEntry> undo, redo;   // only entries whose Original pieces have chunk == 0
    ViewState view;
    bool dirty = false;
    bool read_only = false;
    // persist() could not export the unsaved current state (it referenced too many bytes of an
    // older file version) and exported the last saved state instead.
    bool edits_dropped = false;
    // Targets this document already backed up (or created) on its first save: a restored tab does
    // not replace "<file>.backup" (the original) again.
    std::vector<std::string> backup_done;
};

struct Progress {
    std::atomic<uint64_t> done{0};
    std::atomic<uint64_t> total{0};
    std::atomic<bool> cancel{false};
    // Set by Document while a save is past the point of no return (in-place writes into the file,
    // or the final rename over it): cancel is no longer honoured, the UI shows "Finishing...".
    std::atomic<bool> committing{false};
    double fraction() const {
        uint64_t t = total.load();
        return t ? double(done.load()) / double(t) : 0.0;
    }
};

// What the last save()/save_as() did about the "<target>.backup" copy of the previous file.
struct SaveInfo {
    bool backup_created = false;  // the previous on-disk contents are now at backup_path
    bool backup_skipped = false;  // a backup was due but not made (device, size limit); see note
    std::string backup_path;      // "<target>.backup" when created
    std::string note;             // human-readable reason when skipped
};

class Document {
public:
    // Opens a file for streaming access. Fails only if the file cannot be opened for reading.
    static std::unique_ptr<Document> open_file(const std::string& path, std::string* err = nullptr);
    // New, untitled, empty document ("Untitled 1"...).
    static std::unique_ptr<Document> create_empty(const std::string& display_name);
    // New untitled document pre-filled with bytes (e.g. produced by a script serializer).
    static std::unique_ptr<Document> create_from_bytes(const std::string& display_name,
                                                       const uint8_t* data, size_t len);
    ~Document();

    uint64_t id() const { return id_; }                  // unique per process, never reused
    const std::string& path() const { return path_; }     // "" for untitled
    bool has_path() const { return !path_.empty(); }
    std::string display_name() const;                     // file name or untitled name
    void set_display_name(const std::string& n) { display_name_ = n; }

    // ---- reading -----------------------------------------------------------------------------
    uint64_t size() const { return table_.size(); }
    size_t read(uint64_t offset, uint8_t* dst, size_t len) const;  // bytes copied (clamped to size)
    // Like read(), and `unreadable` (len bytes) gets 1 for every byte that could not be read from
    // disk (I/O error; returned as 0 in dst), 0 for every other one.
    size_t read(uint64_t offset, uint8_t* dst, size_t len, uint8_t* unreadable) const;
    // Sticky: true once a read of any file version this document uses failed (bad sector,
    // unplugged drive, file truncated by another program). Unreadable bytes read as 0.
    bool io_error() const;
    std::shared_ptr<const Snapshot> snapshot() const;
    // True if any byte in [offset, offset+len) is not original file content (typed, pasted, filled,
    // inserted; used to tint edited bytes). Original bytes merely shifted by an insert/erase earlier
    // in the file do not count.
    bool is_modified_range(uint64_t offset, uint64_t len) const;

    // ---- editing (each call is one undo step; returns false if rejected: busy/read-only/range) --
    // `coalesce` merges this edit into the previous undo step when it directly continues it
    // (typing byte after byte); pass true only from interactive typing.
    bool overwrite(uint64_t offset, const uint8_t* data, size_t len, bool coalesce = false);  // may extend the file at EOF
    bool insert(uint64_t offset, const uint8_t* data, size_t len, bool coalesce = false);
    bool erase(uint64_t offset, uint64_t len);
    bool replace(uint64_t offset, uint64_t old_len, const uint8_t* data, size_t len);
    // Fill [offset, offset+len) with a repeating pattern without materialising len bytes in RAM
    // beyond one add-buffer chunk (pattern is written once per chunk and pieces reference it).
    bool fill(uint64_t offset, uint64_t len, const uint8_t* pattern, size_t pattern_len);

    // Group several edits into one undo step (nestable). Used by scripts and multi-step actions.
    // The step's label is the innermost non-empty group label (a labelled doc:transaction inside a
    // script command names the step instead of the command's generic "Script: <name>"); without
    // any, the label of the first edit ("Paste", "Fill", ...).
    void begin_group(const std::string& label = {});
    void end_group();
    bool in_group() const;             // a group is open

    // Bookmarks go through the document so they are part of undo/redo history.
    bool add_bookmark(const Bookmark& b);
    bool remove_bookmark(size_t index);
    bool update_bookmark(size_t index, const Bookmark& b);

    // Full history: undo/redo survive saves (both in-place and rewrite) and restarts (session).
    bool can_undo() const;
    bool can_redo() const;
    bool undo();  // restores pieces + cursor/selection/bookmarks at the time of the action
    bool redo();
    const std::vector<UndoEntry>& undo_stack() const { return undo_; }   // for a History panel
    const std::vector<UndoEntry>& redo_stack() const { return redo_; }
    static constexpr size_t kMaxUndo = 10000;

    // Typing-run limits (app-wide; the app sets them from Settings). A coalesced edit starts a new
    // undo step when the previous one of the run was more than `ms` ago, or when it would grow a
    // run that already covers `max_bytes` bytes (edits inside the run's bytes, e.g. the low nibble
    // of its last byte, still merge). 0 = no limit. Defaults: 500 ms, 32 bytes.
    static void set_undo_merge(int ms, uint64_t max_bytes);
    // Test hook: monotonic clock in milliseconds used by typing-run coalescing; null restores
    // std::chrono::steady_clock.
    static void set_clock_for_tests(int64_t (*now_ms)());

    // ---- state -------------------------------------------------------------------------------
    bool dirty() const;                // differs from the last saved/opened state
    uint64_t generation() const { return generation_; }  // bumps on every content change (incl. undo)
    bool read_only() const { return read_only_; }
    void set_read_only(bool ro) { read_only_ = ro; }
    bool busy() const { return busy_.load(); }  // save in progress
    ViewState& view() { return view_; }
    const ViewState& view() const { return view_; }

    // ---- saving ------------------------------------------------------------------------------
    // save(): if the edit set is size-preserving with every original byte in place, only the
    // modified ranges are written into the existing file (fast even for TB files). Otherwise the
    // whole document is streamed to "<path>.hexer-tmp" next to the target and atomically renamed
    // over it. Undo history is KEPT:
    //   * in-place: before overwriting, the original bytes of every range being written are copied
    //     into the add buffer and history entries that referenced them are remapped to those copies;
    //   * rewrite: the previous file version stays open (POSIX rename semantics / Windows
    //     FILE_RENAME_FLAG_POSIX_SEMANTICS) and remains a source for history entries. If the old
    //     version cannot be kept readable, history before the save is dropped (reported via err).
    // After success the current pieces are the identity over the new file version and dirty()==false.
    // On failure/cancel the original file is untouched (rewrite path) and the document is unchanged.
    // `progress` may be null. Safe to call from a worker thread (sets busy()).
    // save() refuses (returns false) when the file was modified in place by another program since
    // it was opened: the original bytes our pieces refer to are gone, so the result would be a mix
    // of both versions. `force` saves anyway (our edits on top of the current disk contents).
    // If the file was replaced (other inode), the rewrite path streams from the still-open old
    // version. Devices (block devices, raw Windows disks) only accept in-place saves.
    //
    // Backup of the original: when a save writes over an existing file that has no
    // "<target>.backup" yet (per target path: save_as onto another existing file backs that one
    // up too), the on-disk contents are kept as "<target>.backup". An existing .backup is NEVER
    // replaced - it holds the original from before Hexer first saved the file:
    //   * rewrite: the current file gets the second name .backup (hard link), then the new one is
    //     renamed over the target as usual (atomic; no copy; our open handle keeps reading the old
    //     version, so history still works). Without hard links the current file is renamed to
    //     .backup first and the new one moved into place; if that fails the first is rolled back.
    //   * in-place: the file is first copied to ".backup.tmp" with the fastest OS copy (reflink /
    //     copy_file_range / CopyFileExW), then renamed to .backup. The copy counts toward progress
    //     and can be cancelled (nothing is changed then). Files above the size limit are skipped.
    //   * devices are never backed up; targets this document created itself are not either.
    // A failed backup aborts the save before the file is touched. last_save_info() reports it.
    bool save(Progress* progress, std::string* err, bool force = false);
    bool save_as(const std::string& path, Progress* progress, std::string* err);
    SaveInfo last_save_info() const;  // of the last save()/save_as() call (thread-safe)
    // App-wide backup policy (the app sets it from Settings; thread-safe). max_bytes limits the
    // in-place backup copy (0 = no limit). Defaults: enabled, 4 GiB.
    static void set_backup_policy(bool enabled, uint64_t max_bytes);

    // ---- external change detection -----------------------------------------------------------
    // True if the file on disk no longer matches what we opened (size or mtime changed).
    bool changed_on_disk() const;
    FileStat disk_stat() const;        // stat of the file version we last opened/wrote
    // Re-open from disk, discarding all edits and undo history. Keeps view state (clamped).
    bool reload(std::string* err);

    // ---- session support (used by core/session.cpp) ------------------------------------------
    const PieceTable& table() const { return table_; }
    const AddBuffer& add_buffer() const { return add_; }
    const std::shared_ptr<FileSource>& original() const;  // current file version (null if untitled)
    uint32_t current_source() const { return uint32_t(sources_.size()) - 1; }
    // Export state for the session. History entries that reference older file versions (from a
    // rewrite save in this run) are dropped; Original pieces are renumbered to chunk 0.
    PersistedDoc persist() const;
    // False if persist() cannot export the current unsaved state (it references more than 16 MiB
    // of a file version replaced by a save in this run, reachable by undoing past that save): a
    // hot exit would lose it, so the UI should ask before quitting.
    bool hot_exit_safe() const;
    // Rebuild from a PersistedDoc. If the file at `path` no longer matches `file_stat`, the doc is
    // still restored (edits on top of the new contents) and `*changed_on_disk` is set to true.
    // If the file on disk already holds exactly the persisted content (our own save completed but
    // the session was not rewritten before exit), the doc opens clean from disk instead of
    // re-applying the edits, history from before that save is dropped and *note explains it.
    static std::unique_ptr<Document> restore(const PersistedDoc& state, bool* changed_on_disk,
                                             std::string* err, std::string* note = nullptr);
    // Monotonic id of the current content state; lets the session skip re-writing unchanged docs.
    uint64_t state_id() const { return state_id_; }
    // Bumps whenever view state that the session persists may have changed (set by UI on cursor moves).
    uint64_t view_generation = 0;
    // Bumps whenever anything persist() exports may have changed (content, history, bookmarks,
    // saves, reload). Thread-safe; the session uses it to skip unchanged docs.
    uint64_t persist_generation() const { return persist_gen_.load(); }

private:
    Document();
    void push_undo(const char* label, bool coalesce, uint64_t edit_end);
    void after_change();
    bool editable() const;

    // ---- implementation details (all *_locked helpers expect mu_ to be held) ----
    void push_undo(const char* label, bool coalesce, uint64_t edit_begin, uint64_t edit_end);
    void push_entry(std::vector<UndoEntry>& stack, UndoEntry&& e);
    void splice(uint64_t pos, uint64_t del, const std::vector<Piece>& ins);
    UndoEntry capture() const;
    void apply_entry(const UndoEntry& e);
    void apply_pending();       // UI thread only: install history rewritten by a save
    const std::vector<UndoEntry>& eff_undo() const { return pend_ ? pend_undo_ : undo_; }
    const std::vector<UndoEntry>& eff_redo() const { return pend_ ? pend_redo_ : redo_; }
    void prune_sources();       // release file versions no state references any more
    void reclaim_add();         // release add-buffer chunks no state references any more
    void clamp_view();
    bool is_base_piece(const Piece& p) const;
    std::shared_ptr<Snapshot> make_snapshot() const;
    std::string name_locked() const;
    bool save_inplace(const std::string& path, const std::shared_ptr<FileSource>& src, uint32_t cur,
                      const Snapshot& snap, Progress* progress, std::string* err);
    bool save_rewrite(const std::string& target, bool same_file, const Snapshot& snap,
                      Progress* progress, std::string* err);
    // True if this save must first keep `real` (stat `st`) as "<real>.backup"; records skips in
    // last_save_. `copy`: the backup would be a copy (size limit applies).
    bool need_backup_locked(const std::string& real, const FileStat& st, bool copy);
    void backup_done_locked(const std::string& real);

    // Guards table_, add_, sources_, undo_/redo_ (+ pending), path_, display_name_, state ids and
    // disk_stat_ against the save worker. The UI thread takes it in every public method that
    // touches those; the worker only for short commits.
    mutable std::mutex mu_;
    std::string group_label_;
    bool coalesce_open_ = false;          // top undo entry is an open typing run
    int64_t coalesce_last_ms_ = 0;        // clock time of the run's latest edit
    std::vector<std::string> backup_done_;  // targets already backed up (or created) by this doc
    SaveInfo last_save_;
    uint64_t next_state_id_ = 1;
    FileStat disk_stat_;                  // stat of the current file version as we last wrote/opened it
    std::vector<UndoEntry> pend_undo_, pend_redo_;  // history rewritten by a save, not yet installed
    bool pend_ = false;
    uint32_t base_chunks_ = 0;            // untitled docs: add bytes that count as "original"
    uint64_t base_last_used_ = 0;
    std::atomic<uint64_t> persist_gen_{0};
    size_t trims_since_reclaim_ = 0;      // history entries dropped by kMaxUndo since reclaim_add()

    uint64_t id_ = 0;
    std::string path_;
    std::string display_name_;
    std::vector<std::shared_ptr<FileSource>> sources_;  // file versions; back() is current (may hold null for untitled)
    PieceTable table_;
    AddBuffer add_;
    ViewState view_;
    bool read_only_ = false;
    std::atomic<bool> busy_{false};

    std::vector<UndoEntry> undo_, redo_;
    int group_depth_ = 0;
    bool group_pushed_ = false;
    uint64_t generation_ = 0;
    uint64_t state_id_ = 0;
    uint64_t saved_state_id_ = 0;
};

}  // namespace hx
