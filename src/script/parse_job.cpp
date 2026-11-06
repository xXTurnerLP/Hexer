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

bool ScriptEngine::load_job_script(const std::vector<std::string>& dirs, const std::atomic<bool>* cancel,
                                   const std::string& file, const std::string& chunk, const std::string& text) {
    Impl& im = *impl_;
    im.cancel = cancel;
    im.quiet_parse_errors = true;
    dirs_ = dirs;
    add_lib_paths();
    lua_State* L = im.L;
    if (!L) return false;
    if (luaL_loadbufferx(L, text.data(), text.size(), chunk.c_str(), "t") != LUA_OK) {
        lua_pop(L, 1);
        return false;
    }
    im.loading_file = file;
    std::string err;
    const bool ok = im.pcall(0, 0, im.script_limit_ms, &err);
    im.loading_file.clear();
    return ok;
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
        im.progress_fields = &fields_;
        im.progress_offset = &offset_;
        const bool loaded = e.load_job_script(dirs_, &cancel_, file_, chunk_, text_);
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

// ---- DetectJob ------------------------------------------------------------------------------------

DetectJob::DetectJob(ScriptEngine& eng, Document& doc)
    : doc_id_(doc.id()), gen_(doc.generation()), reload_(eng.reload_count()), list_(eng.parsers_) {
    const ScriptEngine::Impl& im = *eng.impl_;
    for (const ParserInfo& p : list_) {
        if (!eng.has_detect(p.name)) continue;  // never a hit (as in detect_parser)
        Entry e;
        e.name = p.name;
        e.file = p.file;
        auto it = im.sources.find(p.file);
        if (it == im.sources.end()) {
            e.state = Entry::Main;  // console / command parser
        } else {
            background_ = true;
            bool have = false;
            for (const auto& s : scripts_) have = have || s.first == p.file;
            if (!have) scripts_.push_back({p.file, {it->second.chunk, it->second.text}});
        }
        entries_.push_back(std::move(e));
    }
    if (!background_) {
        done_ = true;
        return;
    }
    dirs_ = eng.dirs_;
    clone_ = doc.clone_readonly();
    thread_ = std::thread([this] { run(); });
}

DetectJob::~DetectJob() {
    cancel_ = true;
    if (thread_.joinable()) thread_.join();
}

bool DetectJob::wait(int ms) {
    std::unique_lock<std::mutex> lk(m_);
    if (ms < 0) cv_.wait(lk, [this] { return done_.load(); });
    else cv_.wait_for(lk, std::chrono::milliseconds(ms), [this] { return done_.load(); });
    return done_.load();
}

void DetectJob::run() {
    JobHost host;
    host.doc = clone_.get();
    {
        // One engine per script file, made when its first parser's turn comes (nullptr: the
        // script does not load on its own, its parsers detect in the main engine).
        std::vector<std::pair<std::string, std::unique_ptr<ScriptEngine>>> engines;
        auto engine_for = [&](const std::string& file) -> ScriptEngine* {
            for (auto& e : engines)
                if (e.first == file) return e.second.get();
            std::unique_ptr<ScriptEngine> e;
            for (const auto& s : scripts_)
                if (s.first == file) {
                    e = std::make_unique<ScriptEngine>(&host);
                    if (!e->load_job_script(dirs_, &cancel_, file, s.second.chunk, s.second.text)) e.reset();
                    else e->clear_console();  // load-time output is not repeated per detect
                    break;
                }
            engines.emplace_back(file, std::move(e));
            return engines.back().second.get();
        };
        for (Entry& en : entries_) {
            if (cancel_) break;
            if (en.state != Entry::Pending) continue;
            ScriptEngine* e = engine_for(en.file);
            if (cancel_) break;
            if (!e || !e->impl_->parser_refs.count(en.name)) {
                en.state = Entry::Main;  // e.g. needs globals of another script at load time
                continue;
            }
            std::string err;
            const int r = e->run_detect(en.name, *clone_, &err);
            if (cancel_) break;
            for (const ConsoleLine& l : e->console()) out_.push_back({l, false});
            e->clear_console();
            if (r < 0) out_.push_back({{ConsoleLine::Error, "Parser '" + en.name + "' detect: " + err}, true});
            en.state = r > 0 ? Entry::Hit : Entry::Miss;
            if (r > 0) break;  // the answer (later parsers are not asked)
        }
    }
    clone_.reset();
    {
        std::lock_guard<std::mutex> lk(m_);
        done_ = true;
    }
    cv_.notify_all();
}

std::string DetectJob::take(ScriptEngine& eng, Document& doc) {
    wait(-1);
    if (thread_.joinable()) thread_.join();
    for (const Out& o : out_) {
        if (o.once) eng.impl_->log_error_once(o.line.text);
        else eng.log(o.line.kind, o.line.text);
    }
    out_.clear();
    if (cancelled()) return {};
    for (const Entry& en : entries_) {
        if (en.state == Entry::Hit) return en.name;
        if (en.state != Entry::Main) continue;  // Miss
        std::string err;
        const int r = eng.run_detect(en.name, doc, &err);
        if (r < 0) eng.impl_->log_error_once("Parser '" + en.name + "' detect: " + err);
        if (r > 0) return en.name;
    }
    return ScriptEngine::extension_parser(list_, doc);
}

}  // namespace hx
