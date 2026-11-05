#include "core/strings_scan.h"

#include <algorithm>
#include <cstring>
#include <tuple>

namespace hx {

const char* encoding_name(StringEncoding e) {
    switch (e) {
    case StringEncoding::Ascii: return "ASCII";
    case StringEncoding::Utf16LE: return "UTF-16LE";
    case StringEncoding::Utf16BE: return "UTF-16BE";
    }
    return "?";
}

namespace {

// Streaming run detector. Bytes are fed one by one with their absolute offset; every encoding keeps
// its current run, so runs continue across read blocks. UTF-16 keeps one run per offset parity
// (code units at even offsets and at odd offsets are two independent streams).
struct Scanner {
    struct Run {
        uint64_t start = 0;
        uint64_t chars = 0;
    };

    Scanner(const StringsOptions& o, StringsScanResult& r) : opt(o), out(r) {
        min_chars = std::max<uint32_t>(o.min_length, 1);
        for (int c = 0x20; c <= 0x7E; ++c) printable[c] = true;
        printable[uint8_t('\t')] = true;
        if (o.include_newlines) printable[uint8_t('\r')] = printable[uint8_t('\n')] = true;
    }

    void emit(Run& r, StringEncoding e, uint64_t unit) {
        if (r.chars >= min_chars) {
            if (out.hits.size() >= opt.max_results) {
                out.truncated = true;
            } else {
                out.hits.push_back(StringHit{r.start, r.chars * unit, r.chars, e});
            }
        }
        r.chars = 0;
    }

    void step(Run& r, bool ok, uint64_t at, StringEncoding e, uint64_t unit) {
        if (ok) {
            if (r.chars == 0) r.start = at;
            ++r.chars;
        } else if (r.chars) {
            emit(r, e, unit);
        }
    }

    void feed(uint64_t at, uint8_t b) {
        if (opt.ascii) step(ascii, printable[b], at, StringEncoding::Ascii, 1);
        if (have_prev && (opt.utf16le || opt.utf16be)) {
            const uint64_t u = at - 1;  // code unit (prev, b) starts here
            const size_t ph = size_t(u & 1);
            if (opt.utf16le) step(le[ph], b == 0 && printable[prev], u, StringEncoding::Utf16LE, 2);
            if (opt.utf16be) step(be[ph], prev == 0 && printable[b], u, StringEncoding::Utf16BE, 2);
        }
        prev = b;
        have_prev = true;
    }

    void flush() {
        emit(ascii, StringEncoding::Ascii, 1);
        for (Run& r : le) emit(r, StringEncoding::Utf16LE, 2);
        for (Run& r : be) emit(r, StringEncoding::Utf16BE, 2);
    }

    // A hole (unreadable bytes) follows: end every run; no code unit spans it either.
    void cut() {
        flush();
        have_prev = false;
    }

    const StringsOptions& opt;
    StringsScanResult& out;
    uint64_t min_chars = 1;
    bool printable[256] = {};
    Run ascii, le[2], be[2];
    bool have_prev = false;
    uint8_t prev = 0;
};

bool cancelled(const std::atomic<bool>* c) { return c && c->load(std::memory_order_relaxed); }

template <class Src>
std::string hit_text(const Src& src, const StringHit& h, size_t max_chars) {
    const size_t w = h.encoding == StringEncoding::Ascii ? 1 : 2;
    const size_t chars = size_t(std::min<uint64_t>(h.char_count, max_chars));
    std::vector<uint8_t> buf(chars * w);
    const size_t got = buf.empty() ? 0 : src.read(h.offset, buf.data(), buf.size());
    std::string s;
    s.reserve(got / w);
    for (size_t i = 0; i + w <= got; i += w) {
        if (w == 1) {
            s.push_back(char(buf[i]));
        } else {
            // Narrow one code unit; a non-ASCII unit (the document changed since the scan) is '?'.
            const uint8_t lo = h.encoding == StringEncoding::Utf16LE ? buf[i] : buf[i + 1];
            const uint8_t hi = h.encoding == StringEncoding::Utf16LE ? buf[i + 1] : buf[i];
            s.push_back(hi == 0 && lo < 0x80 ? char(lo) : '?');
        }
    }
    return s;
}

char ascii_lower(char c) { return c >= 'A' && c <= 'Z' ? char(c - 'A' + 'a') : c; }

bool is_utf16(StringEncoding e) { return e != StringEncoding::Ascii; }

// True if `s` is the shifted echo of `m`: ASCII text in UTF-16LE ("A\0B\0C\0") also reads as
// UTF-16BE one byte later ("\0B\0C" + the next byte), and the other way round. The echo has the
// other UTF-16 encoding, starts one byte before or after `m`, ends at most one byte past it and is
// not longer (equal length: the LE reading wins).
bool shadow_of(const StringHit& s, const StringHit& m) {
    if (!is_utf16(s.encoding) || !is_utf16(m.encoding) || s.encoding == m.encoding) return false;
    if (s.offset + 1 != m.offset && m.offset + 1 != s.offset) return false;
    if (s.offset + s.byte_length > m.offset + m.byte_length + 1) return false;
    return s.char_count < m.char_count || (s.char_count == m.char_count && m.encoding == StringEncoding::Utf16LE);
}

// With both UTF-16 byte orders on, drops the echo of every string (see shadow_of). `hits` is
// sorted by offset, so the two readings of one string are neighbours (offsets differ by one).
void drop_utf16_echoes(std::vector<StringHit>& hits) {
    std::vector<bool> drop(hits.size(), false);
    for (size_t i = 0; i < hits.size(); ++i) {
        for (size_t j = i + 1; j < hits.size() && hits[j].offset <= hits[i].offset + 1; ++j) {
            if (shadow_of(hits[j], hits[i])) drop[j] = true;
            else if (shadow_of(hits[i], hits[j])) drop[i] = true;
        }
    }
    size_t k = 0;
    for (size_t i = 0; i < hits.size(); ++i)
        if (!drop[i]) hits[k++] = hits[i];
    hits.resize(k);
}

}  // namespace

void scan_strings(const Snapshot& snap, uint64_t begin, uint64_t end, const StringsOptions& opt,
                  StringsScanResult& out, const std::atomic<bool>* cancel, std::atomic<uint64_t>* progress) {
    out = StringsScanResult{};
    end = std::min(end, snap.size());
    begin = std::min(begin, end);
    out.begin = begin;
    out.end = end;
    Scanner sc(opt, out);
    std::vector<uint8_t> buf;
    uint64_t pos = begin;
    while (pos < end && !out.truncated) {
        if (cancelled(cancel)) {
            out.cancelled = true;
            break;
        }
        const size_t n = size_t(std::min<uint64_t>(kStringsBlock, end - pos));
        if (buf.size() < n) buf.resize(n);
        const size_t got = snap.read_valid(pos, buf.data(), n);
        for (size_t i = 0; i < got; ++i) sc.feed(pos + i, buf[i]);
        if (got < n) {
            const uint64_t at = pos + got;
            const uint64_t resume = snap.next_readable(at);
            if (resume <= at) {  // unreadable byte (I/O error): the data ends here
                if (progress) progress->fetch_add(n, std::memory_order_relaxed);
                out.io_error = true;
                out.io_error_offset = at;
                break;
            }
            // A hole of a sparse source (unmapped memory): strings end at it; continue behind it.
            sc.cut();
            const uint64_t to = std::min(resume, end);
            out.skipped += to - at;
            if (progress) progress->fetch_add(to - pos, std::memory_order_relaxed);
            pos = to;
            continue;
        }
        if (progress) progress->fetch_add(n, std::memory_order_relaxed);
        pos += n;
    }
    if (!out.cancelled) sc.flush();  // a cancelled scan does not report its cut-off runs
    std::sort(out.hits.begin(), out.hits.end(), [](const StringHit& a, const StringHit& b) {
        return std::tie(a.offset, a.encoding) < std::tie(b.offset, b.encoding);
    });
    if (opt.utf16le && opt.utf16be) drop_utf16_echoes(out.hits);
}

std::string string_hit_text(const Snapshot& snap, const StringHit& hit, size_t max_chars) {
    return hit_text(snap, hit, max_chars);
}

std::string string_hit_text(const Document& doc, const StringHit& hit, size_t max_chars) {
    return hit_text(doc, hit, max_chars);
}

std::string escape_string_text(const std::string& text) {
    static const char* kHex = "0123456789ABCDEF";
    std::string s;
    s.reserve(text.size());
    for (char ch : text) {
        const uint8_t c = uint8_t(ch);
        if (c == '\t') s += "\\t";
        else if (c == '\r') s += "\\r";
        else if (c == '\n') s += "\\n";
        else if (c < 0x20 || c >= 0x7F) {
            s += "\\x";
            s.push_back(kHex[c >> 4]);
            s.push_back(kHex[c & 15]);
        } else {
            s.push_back(ch);
        }
    }
    return s;
}

// ---- filter -------------------------------------------------------------------------------------

void StringsFilter::reset(const std::string& needle) {
    needle_ = needle;
    for (char& c : needle_) c = ascii_lower(c);
    tested_ = 0;
    matches_.clear();
}

bool StringsFilter::step(const Snapshot& snap, const std::vector<StringHit>& hits, size_t max_hits) {
    const size_t end = std::min(hits.size(), tested_ + std::max<size_t>(max_hits, 1));
    for (; tested_ < end; ++tested_) {
        if (!needle_.empty()) {
            if (hits[tested_].char_count < needle_.size()) continue;
            std::string t = string_hit_text(snap, hits[tested_], 256);
            for (char& c : t) c = ascii_lower(c);
            if (t.find(needle_) == std::string::npos) continue;
        }
        matches_.push_back(tested_);
    }
    return done(hits.size());
}

// ---- background job -----------------------------------------------------------------------------

struct StringsJob::Run {
    std::atomic<bool> cancel{false};
    std::atomic<bool> finished{false};  // worker is about to exit: joining it does not block
    std::atomic<uint64_t> done{0};
    uint64_t total = 0;
};

StringsJob::~StringsJob() {
    for (auto& t : threads_) t.second->cancel = true;
    for (auto& t : threads_) t.first.join();
}

std::shared_ptr<StringsJob::Run> StringsJob::current() const {
    std::lock_guard<std::mutex> lock(mu_);
    return run_;
}

void StringsJob::cancel() {
    if (auto r = current()) r->cancel = true;
}

bool StringsJob::running() const { return running_.load(); }

double StringsJob::progress() const {
    auto r = current();
    const uint64_t t = r ? r->total : 0, d = r ? r->done.load() : 0;
    if (!t) return running_.load() ? 0.0 : 1.0;
    return d >= t ? 1.0 : double(d) / double(t);
}

uint64_t StringsJob::generation() const { return generation_.load(); }

std::shared_ptr<const StringsJob::Result> StringsJob::result() const {
    std::lock_guard<std::mutex> lock(mu_);
    return result_;
}

void StringsJob::start(std::shared_ptr<const Snapshot> snap, uint64_t begin, uint64_t end, StringsOptions opt) {
    auto run = std::make_shared<Run>();
    if (snap) {
        const uint64_t e = std::min(end, snap->size());
        run->total = e > begin ? e - begin : 0;
    }
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (run_) run_->cancel = true;
        run_ = run;
    }
    for (auto it = threads_.begin(); it != threads_.end();) {
        if (it->second->finished) {
            it->first.join();
            it = threads_.erase(it);
        } else {
            ++it;
        }
    }
    running_ = true;
    std::thread th([this, run, snap = std::move(snap), begin, end, opt]() {
        auto r = std::make_shared<Result>();
        r->options = opt;
        r->snap = snap;
        if (snap) scan_strings(*snap, begin, end, opt, r->scan, &run->cancel, &run->done);
        else r->scan.cancelled = run->cancel.load();
        {
            std::lock_guard<std::mutex> lock(mu_);
            if (run_ == run) {  // superseded runs publish nothing
                result_ = std::move(r);
                run->done = run->total;
                running_ = false;
                generation_.fetch_add(1);
            }
        }
        run->finished = true;
    });
    threads_.emplace_back(std::move(th), std::move(run));
}

}  // namespace hx
