#pragma once
// Sublime-style hot exit: every open tab, its unsaved edits, cursor/scroll/bookmarks are persisted
// to the session directory periodically and on exit, and restored on startup - no "save changes?"
// prompts. Only the *edits* are stored (piece list + referenced add bytes), never the original
// file, so a session over a 2 TB image stays tiny.
//
// Layout of <session_dir>:
//   session.ini         ordered tab list + active tab (key=value lines, written atomically)
//   doc-<n>.hxs         one binary file per document (magic "HXS1", little-endian, versioned)
//   lock                held (OS file lock) by the instance that owns this directory
//   instance-<k>/       same layout, used by further Hexer instances running at the same time;
//                       the next instance that owns the main directory adopts their documents
//
// Documents whose file cannot be restored right now (file on an unplugged drive / offline share /
// locked, session file unreadable or written by another Hexer version) stay in the index and on
// disk for a later session (see kept()); only files failing the integrity check are dropped.
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
    };
    Restored load();

    void clear();  // delete all session files (of this instance's directory)
    const std::string& dir() const { return dir_; }

    // Session files that load() could not restore but kept for a later session.
    const std::vector<std::string>& kept() const { return kept_; }
    void discard_kept();  // give up on them (deleted; the index is rewritten by the next save())
    // True if another running instance owns dir(): this one persists into instance-<k>/.
    bool secondary();

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
};

}  // namespace hx
