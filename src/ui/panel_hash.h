#pragma once
// "Hashes" panel: checksums and hashes (core/hash.h) of the selection, or of the whole file when
// nothing is selected / "Whole file" is ticked. Self-contained (no App dependency): the app owns one
// HashPanel and calls draw() every frame with the active document.
//
//   * Ranges up to kAutoLimit (64 MiB) are recomputed automatically ~150 ms after the selection,
//     the document or the algorithm set stopped changing; larger ones need the Compute button.
//     Hashing always runs on a HashJob worker thread over a Snapshot (progress bar + Cancel).
//   * Results table Algorithm | Value (monospace). Click a row to copy the value; right-click for
//     "Copy as 0x...", uppercase and "Copy all".
//   * "Expected" input: a row whose value matches (hex, optional 0x, any case, spaces/colons
//     ignored) is highlighted green.
//   * Values computed for an older document state / another range are marked stale.
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "core/hash.h"

struct ImFont;

namespace hx {

class Document;

struct HashPanelCallbacks {
    // Puts text on the clipboard. Optional; default ImGui::SetClipboardText.
    std::function<void(const std::string& text)> copy;
    // Short user-facing notice, e.g. for the status bar ("Copied SHA-256"). Optional.
    std::function<void(const std::string& message)> status;
};

class HashPanel {
public:
    static constexpr uint64_t kAutoLimit = uint64_t(64) << 20;  // auto-compute up to this many bytes

    HashPanel();  // the default algorithms (HashAlgorithm::is_default) are selected

    // Draws the window `title` (Begin/End inside; `open` may be null). `doc` is the active document
    // or nullptr; a busy (saving) document is not touched. `mono` is the font for values (nullptr =
    // current font), `ui_scale` scales fixed widths.
    void draw(const char* title, bool* open, const Document* doc, ImFont* mono, float ui_scale,
              const HashPanelCallbacks& cb = {});

    // Start hashing the current range on the next draw() (e.g. from a menu / palette action).
    void request_compute() { compute_requested_ = true; }
    // A hash is running or an automatic one is about to start: the host should keep drawing
    // frames (instead of waiting for input) so the debounce fires and progress shows.
    bool wants_frames() const { return job_.running() || pending_since_ >= 0.0; }

    // Selected algorithms by display name (for persisting in settings). Unknown names are ignored.
    std::vector<std::string> selected() const;
    void set_selected(const std::vector<std::string>& names);

    bool whole_file = false;   // hash the whole file even when there is a selection
    std::string expected;      // the "Expected" input

private:
    struct Key {               // what a result was computed for
        uint64_t doc_id = 0, gen = 0, offset = 0, length = 0;
        uint32_t algos = 0;    // bit i = hash_algorithms()[i]
        bool operator==(const Key&) const = default;
    };
    void start(const Document& doc, const Key& k);
    void draw_algorithm_popup();
    void draw_results(ImFont* mono, float ui_scale, const HashPanelCallbacks& cb);

    uint32_t algos_ = 0;
    HashJob job_;
    uint64_t seen_gen_ = 0;    // last job generation consumed
    Key job_key_;              // key of the most recently started run
    bool have_result_ = false;
    Key result_key_;
    HashJob::Result result_;
    Key pending_key_;          // debounce: key seen since pending_since_
    double pending_since_ = -1.0;
    bool have_no_auto_ = false;
    Key no_auto_key_;          // the user cancelled this one: do not auto-restart it
    bool compute_requested_ = false;
};

}  // namespace hx
