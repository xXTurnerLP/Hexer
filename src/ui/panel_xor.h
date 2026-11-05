#pragma once
// "XOR Brute Force" panel: finds simply obfuscated copies of a known plaintext (XOR / ADD / ROL with
// a 1-byte key, XOR with a 2..16 byte key; core/xorscan.h) in the whole file or the selection on a
// worker thread, guesses XOR keys of zero-heavy (or space-heavy) data from the selection, and
// decodes the selection with a chosen key as one undoable edit.
//
// Self-contained: knows nothing about App; the host passes the active document and callbacks.
// Results are kept per document (Document::id()); call forget() when a document is closed.
//
//   * Known plaintext: text with C escapes ("PE\0\0", "\x89PNG") or hex bytes (Hex toggle converts
//     the current input); presets MZ, PE\0\0, http, This program, \x89PNG.
//   * Results table Offset | Transform | Key | Decoded (the bytes at the hit decoded with its key).
//     Click = jump (select the match) and choose its key; right-click: copy offset / key.
//   * Guess tab: candidate keys of the selection (first 256 KiB) ranked by score, with a preview
//     of its first 64 bytes decoded; click a candidate to choose it.
//   * "Decode selection" applies the chosen key to the selection (phase = key index of the
//     selection start, keys use the absolute-offset convention of core/xorscan.h).
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "core/xorscan.h"

struct ImFont;

namespace hx {

class Document;
struct Settings;

struct XorPanelCallbacks {
    std::function<void(uint64_t offset, uint64_t len)> jump;  // select [offset, offset+len) and reveal it
    // Decode the active document's selection with (t, key, phase) as one undoable edit. Optional:
    // when empty the panel calls hx::apply_transform(doc, sel_begin, sel_len, t, key, phase, true)
    // itself and reports the outcome through notify.
    std::function<void(XorTransform t, const std::vector<uint8_t>& key, uint64_t phase)> apply;
    std::function<void(const std::string& text)> copy;        // clipboard (optional; default ImGui)
    std::function<void(const std::string& msg)> notify;       // short status-bar message
};

struct XorPanel {
    XorPanel();
    ~XorPanel();
    XorPanel(const XorPanel&) = delete;
    XorPanel& operator=(const XorPanel&) = delete;

    std::string plaintext = "This program";  // the known-plaintext input
    bool plaintext_hex = false;              // input is hex bytes (else text with C escapes)
    XorScanOptions options;                  // transforms to try (shared by all documents)
    bool selection_only = false;             // scan the selection instead of the whole file
    bool guess_spaces = false;               // key guess assumes ' ' (text) instead of 0x00
    ImFont* mono = nullptr;                  // offsets / keys / previews (nullptr = current font)
    float ui_scale = 1.0f;

    static constexpr size_t kGuessMax = size_t(256) << 10;  // bytes of the selection key_guess reads

    // Options <-> settings.ini (Settings::xor_*: the transforms and the key length): load_settings at startup; save_settings writes
    // them back and returns true when one changed (the host then saves settings.ini).
    void load_settings(const Settings& s);
    bool save_settings(Settings& s) const;

    // Draws the panel contents into the current window (the caller owns Begin/End). `doc` may be
    // null. Only "Decode selection" changes the document (through cb.apply / Document undo).
    void draw(Document* doc, const XorPanelCallbacks& cb);
    void forget(uint64_t doc_id);  // drops the results (and cancels the scan) of a closed document
    // Start a scan (of the selection or the whole file) on the next draw(), as the Scan button does.
    void request_scan(bool selection) {
        selection_only = selection;
        scan_requested_ = true;
    }
    // Run "Guess key from selection" on the next draw() (palette action) and show the Guess tab.
    void request_guess() { guess_requested_ = true; }
    // A scan is running: the host should keep drawing frames so progress / results show up.
    bool wants_frames() const { return wants_frames_; }

private:
    struct DocState;
    DocState& state(uint64_t doc_id);
    void draw_scan_tab(Document& doc, DocState& st, const XorPanelCallbacks& cb);
    void draw_guess_tab(Document& doc, DocState& st, const XorPanelCallbacks& cb);
    std::map<uint64_t, std::unique_ptr<DocState>> docs_;
    bool scan_requested_ = false;
    bool guess_requested_ = false;
    bool wants_frames_ = false;
};

}  // namespace hx
