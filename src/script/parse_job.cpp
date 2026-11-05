// ParseJob: a parse in a ScriptEngine of its own on a worker thread (see parse_job.h).
#include "script/parse_job.h"

#include <chrono>
#include <utility>

#include "script/lua_internal.h"

namespace hx {
namespace {

// The worker's view of the app: one read-only document, nothing else.
struct JobHost : ScriptHost {
    Document* doc = nullptr;
    bool have_view = false;
    uint64_t first = 0, last = 0;

    Document* active_document() override { return doc; }
    Document* find_document(uint64_t id) override { return doc && doc->id() == id ? doc : nullptr; }
    Document* open_bytes(const std::string&, const uint8_t*, size_t) override { return nullptr; }
    void reveal(Document&, uint64_t, uint64_t) override {}
    bool view_range(Document&, uint64_t& f, uint64_t& l) override {
        f = first;
        l = last;
        return have_view;
    }
};

}  // namespace

ParseJob::ParseJob(ScriptEngine& eng, Document& doc, const std::string& parser, uint64_t base, uint64_t length)
    : parser_(parser), base_(base), length_(length), doc_id_(doc.id()), gen_(doc.generation()) {
    const ScriptEngine::Impl& im = *eng.impl_;
    const ScriptEngine::Impl::ScriptText* src = nullptr;
    if (im.parser_refs.count(parser))
        for (const ParserInfo& p : eng.parsers_)
            if (p.name == parser) {
                auto it = im.sources.find(p.file);
                if (it != im.sources.end()) {
                    src = &it->second;
                    file_ = p.file;
                }
                break;
            }
    if (!src) {  // console / command parser (or an unknown name): take() runs it synchronously
        sync_ = true;
        done_ = true;
        return;
    }
    chunk_ = src->chunk;
    text_ = src->text;
    dirs_ = eng.dirs_;
    if (ScriptHost* h = eng.host()) have_view_ = h->view_range(doc, view_first_, view_last_);
    clone_ = doc.clone_readonly();
    thread_ = std::thread([this] { run(); });
}

ParseJob::~ParseJob() {
    cancel_ = true;
    if (thread_.joinable()) thread_.join();
}

bool ParseJob::wait(int ms) {
    std::unique_lock<std::mutex> lk(m_);
    if (ms < 0) cv_.wait(lk, [this] { return done_.load(); });
    else cv_.wait_for(lk, std::chrono::milliseconds(ms), [this] { return done_.load(); });
    return done_.load();
}

void ParseJob::run() {
    JobHost host;
    host.doc = clone_.get();
    host.have_view = have_view_;
    host.first = view_first_;
    host.last = view_last_;
    {
        ScriptEngine e(&host);
        ScriptEngine::Impl& im = *e.impl_;
        im.cancel = &cancel_;
        im.progress_fields = &fields_;
        im.progress_offset = &offset_;
        im.quiet_parse_errors = true;
        e.dirs_ = dirs_;
        e.add_lib_paths();
        bool loaded = false;
        if (lua_State* L = im.L) {
            if (luaL_loadbufferx(L, text_.data(), text_.size(), chunk_.c_str(), "t") == LUA_OK) {
                im.loading_file = file_;
                std::string err;
                loaded = im.pcall(0, 0, im.script_limit_ms, &err);
                im.loading_file.clear();
            } else {
                lua_pop(L, 1);
            }
        }
        if (cancel_) {
            result_.parser = parser_;
            result_.error = "parse cancelled";
            result_.doc_generation = gen_;
        } else if (!loaded || !im.parser_refs.count(parser_)) {
            sync_ = true;  // the script needs the main state (e.g. globals of another script)
        } else {
            e.clear_console();  // what the script printed while loading is not repeated per parse
            result_ = e.parse(*clone_, parser_, base_, length_);
            error_full_ = im.last_parse_error;
            log_.assign(e.console().begin(), e.console().end());
        }
    }
    clone_.reset();
    {
        std::lock_guard<std::mutex> lk(m_);
        done_ = true;
    }
    cv_.notify_all();
}

ParseResult ParseJob::take(ScriptEngine& eng, Document& doc) {
    wait(-1);
    if (thread_.joinable()) thread_.join();
    if (sync_) return eng.parse(doc, parser_, base_, length_);
    for (const ConsoleLine& l : log_) eng.log(l.kind, l.text);
    log_.clear();
    if (!result_.error.empty() && !cancelled())
        eng.impl_->log_error_once("Parser '" + parser_ + "': " + (error_full_.empty() ? result_.error : error_full_));
    return std::move(result_);
}

}  // namespace hx
