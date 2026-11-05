#pragma once
// Sublime-style hot exit: every open tab, its unsaved edits, cursor/scroll/bookmarks are persisted
// to the session directory periodically and on exit, and restored on startup - no "save changes?"
// prompts. Only the *edits* are stored (piece list + referenced add bytes), never the original
// file, so a session over a 2 TB image stays tiny.
//
// Layout of <session_dir>:
//   session.ini         ordered tab list + active tab (key=value lines, written atomically), each
//                       doc's id at save time ("docid=", after its "doc=" line) and the session
//                       extras ("x.<key>=<value>", %XX-escaped); older builds ignore those lines
//   doc-<n>.hxs         one binary file per document (magic "HXS1", little-endian, versioned;
//                       v3 adds the doc's extras, see PersistedDoc::extras)
//   lock                held (OS file lock) by the instance that owns this directory
//   instance-<k>/       same layout, used by further Hexer instances running at the same time;
//                       the next instance that owns the main directory adopts their documents
//   inbox/<pid>-<n>.paths  single instance: files a second Hexer process forwarded to the one
//                       that owns the main directory (one UTF-8 path per line; empty = only
//                       "come to the front"). Claimed by renaming to .taken, then deleted.
//
// Documents whose file cannot be restored right now (file on an unplugged drive / offline share /
// locked, session file unreadable or written by another Hexer version) stay in the index and on
// disk for a later session (see kept()); only files failing the integrity check are dropped.
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "core/document.h"
#include "core/os_file.h"

namespace hx {

class Session {
public:
    explicit Session(std::string dir);
    ~Session();

    // Persist all docs. Cheap when nothing changed: a doc file is only rewritten when the
    // document's state_id()/view changed since the last call. Removes files of closed docs.
    bool save(const std::vector<Document*>& docs, int active_index, std::string* err = nullptr);

    struct Restored {
        std::vector<std::unique_ptr<Document>> docs;
        int active_index = 0;
        // Human-readable problems, e.g. "data.bin changed on disk since last session; edits were
        // restored on top of the new contents" or "missing.bin no longer exists (skipped)".
        std::vector<std::string> warnings;
        // Parallel to docs: the Document::id() each doc had when the session was saved, so
        // session extras that reference docs by id can be mapped to the restored ones. 0 = unknown
        // (index written by an older build, or doc adopted from another instance's directory).
        std::vector<uint64_t> saved_ids;
    };
    Restored load();

    void clear();  // delete all session files (of this instance's directory); also clears extras

    // ---- session-level UI state: opaque, binary-safe key/value pairs ---------------------------
    // For state spanning documents (per-doc state goes to Document::set_extra). Written into the
    // index by every save(); load() replaces them with those of this instance's directory (never
    // merged from adopted instances). Keys the app uses:
    //   "compare.<n>" = "<docidA>|<docidB>|<shift>"  a Compare tab: Document::id()s at save time
    //                   (map with Restored::saved_ids), shift = signed byte offset of B (decimal)
    //   "active"      = the active tab when it is not a plain doc tab, e.g. "compare.<n>"
    void set_extra(const std::string& key, const std::string& value);  // "" erases
    std::string extra(const std::string& key) const;                   // "" if unset
    const std::map<std::string, std::string>& extras() const { return extras_; }
    const std::string& dir() const { return dir_; }

    // Session files that load() could not restore but kept for a later session.
    const std::vector<std::string>& kept() const { return kept_; }
    void discard_kept();  // give up on them (deleted; the index is rewritten by the next save())
    // True if another running instance owns dir(): this one persists into instance-<k>/.
    bool secondary();
    // True if this instance owns dir() itself (and so receives forwarded files, see inbox_take).
    bool primary();

private:
    struct Saved {
        uint64_t doc_id = 0, state_id = 0;
        std::string file;        // "" = not written to this instance's directory yet (adopted)
        std::string view_hash;
        FileStat disk;           // doc's disk_stat() when the file was last written
        bool written = false;
    };
    struct Adopted {             // instance-<k> dir of a finished secondary instance
        std::string dir;
        std::vector<std::string> failed;  // entries that could not be restored: stay there
        std::unique_ptr<OsLock> lock;
    };
    bool acquire();
    int load_dir(const std::string& dir, Restored& out, Adopted* adopt);
    void finish_adoption();

    std::string dir_;
    std::string slot_dir_;       // dir_ or dir_/instance-<k>; "" until acquire()
    bool lock_tried_ = false;
    std::unique_ptr<OsLock> lock_;
    std::vector<Saved> saved_;
    std::vector<std::string> kept_;
    std::vector<Adopted> adopted_;
    std::map<std::string, std::string> extras_;
};

// ---- single instance (Sublime-like): a second process forwards its files and exits ----------
// True if a running process holds the lock of the main session directory `dir` right now.
bool session_primary_running(const std::string& dir);
// Atomically writes a new "<dir>/inbox/<pid>-<n>.paths" holding `files` (absolute paths); *posted
// gets its path (for inbox_withdraw).
bool inbox_post(const std::string& dir, const std::vector<std::string>& files, std::string* posted,
                std::string* err = nullptr);
// Takes every message in "<dir>/inbox" (in name order), including ones a crashed instance
// left behind: claims (renames), reads and deletes each. One path list per message.
std::vector<std::vector<std::string>> inbox_take(const std::string& dir);
// Withdraws a posted message; false if it was already taken (the running instance has it).
bool inbox_withdraw(const std::string& posted);

}  // namespace hx
