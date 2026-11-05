#pragma once
// Sublime-style hot exit: every open tab, its unsaved edits, cursor/scroll/bookmarks are persisted
// to the session directory periodically and on exit, and restored on startup - no "save changes?"
// prompts. Only the *edits* are stored (piece list + referenced add bytes), never the original
// file, so a session over a 2 TB image stays tiny.
//
// Layout of <session_dir>:
//   session.ini         ordered tab list + active tab (key=value lines, written atomically)
//   doc-<n>.hxs         one binary file per document (magic "HXS1", little-endian, versioned)
#include <memory>
#include <string>
#include <vector>

#include "core/document.h"

namespace hx {

class Session {
public:
    explicit Session(std::string dir);

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

    void clear();  // delete all session files
    const std::string& dir() const { return dir_; }

private:
    std::string dir_;
    struct Saved { uint64_t doc_id, state_id; std::string file; std::string view_hash; };
    std::vector<Saved> saved_;
};

}  // namespace hx
