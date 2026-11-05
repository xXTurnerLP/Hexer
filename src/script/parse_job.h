#pragma once
// ParseJob: one ScriptEngine::parse on a worker thread, so a slow parser never blocks the UI.
//
// The worker runs the parser in a Lua state of its own: a fresh ScriptEngine whose host knows
// only a read-only clone of the document (Document::clone_readonly) and which ran nothing but the
// script the parser came from (its source as of the last reload / run_source; require() finds
// the same lib/ modules). The Lua parser API is unchanged; inside a background parse:
//   * doc reads see the content as it was when the job started (hx.doc() is that document too);
//     edits raise "document is read-only"; hx.highlight, doc:select / doc:jump, bookmarks and
//     hx.new_doc have no visible effect; doc:view_range() is the range shown at the start;
//   * globals set by other script files are not visible (share code through require);
//   * print / hx.log / warnings are buffered and reach the console when the UI takes the result;
//     a parse error is logged once per script reload, as for a synchronous parse.
// Limits as ScriptEngine::parse (~2 s, 200,000 fields). cancel() stops the parser at its next
// instruction-count check: the partial tree is kept, error "parse cancelled".
// A parser that cannot be rebuilt that way (registered from the console or a running command,
// or whose script does not load on its own) is parsed synchronously in the main engine by take().
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "core/document.h"
#include "script/script_engine.h"

namespace hx {

class ParseJob {
public:
    // Starts parsing [base, base + length) of `doc` with parser `parser` (as ScriptEngine::parse:
    // length UINT64_MAX = to EOF, clamped to the document) and returns at once. UI thread: it
    // copies everything the worker needs, the worker never touches `eng` or `doc`.
    ParseJob(ScriptEngine& eng, Document& doc, const std::string& parser, uint64_t base = 0,
             uint64_t length = UINT64_MAX);
    ~ParseJob();  // cancels and waits for the worker
    ParseJob(const ParseJob&) = delete;
    ParseJob& operator=(const ParseJob&) = delete;

    // What it parses.
    const std::string& parser() const { return parser_; }
    uint64_t base() const { return base_; }
    uint64_t length() const { return length_; }
    uint64_t doc_id() const { return doc_id_; }
    uint64_t generation() const { return gen_; }  // Document::generation() at the start
    bool background() const { return !sync_; }   // false: take() parses in the main engine

    bool done() const { return done_.load(); }
    bool wait(int ms);                          // waits up to `ms` (< 0: forever); returns done()
    void cancel() { cancel_ = true; }
    bool cancelled() const { return cancel_.load(); }
    // Progress while it runs (any thread): fields emitted so far and the absolute end offset of
    // the last one.
    uint64_t fields() const { return fields_.load(std::memory_order_relaxed); }
    uint64_t offset() const { return offset_.load(std::memory_order_relaxed); }

    // UI thread, once, after done(): the result (doc_generation = generation()). Moves the
    // parser's buffered console output into `eng`'s console (a cancelled job's error is not
    // logged). A synchronous job parses `doc` here, which must still be at generation().
    ParseResult take(ScriptEngine& eng, Document& doc);

private:
    void run();  // the worker

    std::string parser_;
    uint64_t base_ = 0, length_ = UINT64_MAX, doc_id_ = 0, gen_ = 0;
    bool sync_ = false;               // written before done_ (worker), read after it

    // Inputs of the worker (copied on the UI thread).
    std::unique_ptr<Document> clone_;
    std::string file_, chunk_, text_; // the parser's script: ParserInfo::file, chunk name, source
    std::vector<std::string> dirs_;   // script dirs (require paths)
    bool have_view_ = false;
    uint64_t view_first_ = 0, view_last_ = 0;

    // Outputs (valid once done()).
    ParseResult result_;
    std::vector<ConsoleLine> log_;
    std::string error_full_;          // parse error with traceback

    std::atomic<bool> cancel_{false}, done_{false};
    std::atomic<uint64_t> fields_{0}, offset_{0};
    std::mutex m_;
    std::condition_variable cv_;
    std::thread thread_;
};

}  // namespace hx
