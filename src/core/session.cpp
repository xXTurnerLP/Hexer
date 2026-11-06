#include "core/session.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <map>
#include <new>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "core/os_file.h"

namespace hx {

namespace {

constexpr char kMagic[4] = {'H', 'X', 'S', '1'};
// 2: bookmarks carry a note; edits_dropped is always written, then the backed-up targets.
// 3: v2 + an extension block (u32 byte length, then u32 count + key/value strings: the doc's
//    extras). Only written when the doc has extras, so files without them stay readable by v2
//    builds. A malformed block (length right, contents not) drops the extras, not the doc.
// 4: every history entry carries its time (i64 ms since the epoch) and a flags byte (bit 0 view
//    step, bit 1 view options follow: u8 read-only, str parser, u64 parse base, u64 parse length);
//    the view gets the Parse at range (u64 base, u64 length; v3 kept it in the extras
//    "parse.base" / "parse.length", moved over on load); after the backed-up targets come the ref
//    files (u32 count, then str path + u64 size + u64 mtime each: Original pieces with chunk k >= 1
//    read ref file k - 1); the extension block is always present. Always written (the timestamps).
// Versions 1 to 3 are still read; a newer file is kept for the Hexer that wrote it.
constexpr uint32_t kVersion = 4;
constexpr const char* kIndexFile = "session.ini";

uint32_t crc32(const uint8_t* p, size_t n) {
    static uint32_t table[256];
    static bool init = [] {
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t c = i;
            for (int k = 0; k < 8; ++k) c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
            table[i] = c;
        }
        return true;
    }();
    (void)init;
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; ++i) c = table[(c ^ p[i]) & 0xFF] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

// ---- little-endian writer / bounds-checked reader --------------------------------------------
struct Writer {
    std::string b;
    void u8(uint8_t v) { b.push_back(char(v)); }
    void u32(uint32_t v) {
        for (int i = 0; i < 4; ++i) b.push_back(char((v >> (8 * i)) & 0xFF));
    }
    void u64(uint64_t v) {
        for (int i = 0; i < 8; ++i) b.push_back(char((v >> (8 * i)) & 0xFF));
    }
    void bytes(const void* p, size_t n) { b.append(static_cast<const char*>(p), n); }
    void str(const std::string& s) {
        u32(uint32_t(s.size()));
        bytes(s.data(), s.size());
    }
    void piece(const Piece& p) {
        u8(p.src);
        u32(p.chunk);
        u64(p.start);
        u64(p.len);
    }
    void pieces(const std::vector<Piece>& ps) {
        u32(uint32_t(ps.size()));
        for (const Piece& p : ps) piece(p);
    }
    void bookmarks(const std::vector<Bookmark>& bs) {
        u32(uint32_t(bs.size()));
        for (const Bookmark& bm : bs) {
            u64(bm.offset);
            u64(bm.length);
            str(bm.name);
            u32(bm.color);
            str(bm.note);
        }
    }
    void entries(const std::vector<UndoEntry>& es) {
        u32(uint32_t(es.size()));
        for (const UndoEntry& e : es) {
            pieces(e.pieces);
            u64(e.cursor);
            u64(e.anchor);
            bookmarks(e.bookmarks);
            u64(e.state_id);
            u64(e.coalesce_begin);
            u64(e.coalesce_end);
            str(e.label);
            u64(uint64_t(e.time_ms));
            u8(uint8_t((e.view_only ? 1 : 0) | (e.has_view ? 2 : 0)));
            if (e.has_view) {
                u8(e.view.read_only);
                str(e.view.parser);
                u64(e.view.parse_base);
                u64(e.view.parse_length);
            }
        }
    }
};

struct Reader {
    const uint8_t* p;
    size_t n;
    size_t pos = 0;
    bool ok = true;
    uint32_t version = kVersion;  // format version of the file being read

    bool need(size_t k) {
        if (!ok || n - pos < k) ok = false;
        return ok;
    }
    uint8_t u8() { return need(1) ? p[pos++] : 0; }
    uint32_t u32() {
        if (!need(4)) return 0;
        uint32_t v = 0;
        for (int i = 0; i < 4; ++i) v |= uint32_t(p[pos + i]) << (8 * i);
        pos += 4;
        return v;
    }
    uint64_t u64() {
        if (!need(8)) return 0;
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i) v |= uint64_t(p[pos + i]) << (8 * i);
        pos += 8;
        return v;
    }
    // Element count whose elements need at least `min_size` bytes each (guards huge allocations).
    uint32_t count(size_t min_size) {
        uint32_t c = u32();
        if (ok && min_size && uint64_t(c) * min_size > n - pos) ok = false;
        return ok ? c : 0;
    }
    std::string str() {
        uint32_t len = count(1);
        if (!need(len)) return {};
        std::string s(reinterpret_cast<const char*>(p + pos), len);
        pos += len;
        return s;
    }
    Piece piece() {
        Piece pc;
        uint8_t src = u8();
        if (src > Piece::Add) ok = false;
        pc.src = Piece::Src(src);
        pc.chunk = u32();
        pc.start = u64();
        pc.len = u64();
        return pc;
    }
    std::vector<Piece> pieces() {
        std::vector<Piece> ps(count(21));
        for (Piece& pc : ps) pc = piece();
        return ps;
    }
    std::vector<Bookmark> bookmarks() {
        std::vector<Bookmark> bs(count(24));
        for (Bookmark& b : bs) {
            b.offset = u64();
            b.length = u64();
            b.name = str();
            b.color = u32();
            if (version >= 2) b.note = str();
        }
        return bs;
    }
    std::vector<UndoEntry> entries() {
        std::vector<UndoEntry> es(count(56));
        for (UndoEntry& e : es) {
            e.pieces = pieces();
            e.cursor = u64();
            e.anchor = u64();
            e.bookmarks = bookmarks();
            e.state_id = u64();
            e.coalesce_begin = u64();
            e.coalesce_end = u64();
            e.label = str();
            if (version >= 4) {
                e.time_ms = int64_t(u64());
                const uint8_t flags = u8();
                if (flags & ~3u) ok = false;
                e.view_only = (flags & 1) != 0;
                e.has_view = (flags & 2) != 0;
                if (e.view_only && (!e.has_view || !e.pieces.empty())) ok = false;
                if (e.has_view) {
                    e.view.read_only = u8() != 0;
                    e.view.parser = str();
                    e.view.parse_base = u64();
                    e.view.parse_length = u64();
                }
            }
            if (!ok) break;
        }
        return es;
    }
};

std::string serialize(const PersistedDoc& d) {
    Writer w;
    w.bytes(kMagic, 4);
    w.u32(kVersion);
    w.str(d.path);
    w.str(d.display_name);
    w.u8(d.file_stat.exists);
    w.u8(d.file_stat.is_dir);
    w.u64(d.file_stat.size);
    w.u64(uint64_t(d.file_stat.mtime_ns));
    w.pieces(d.pieces);
    w.u32(uint32_t(d.add_chunks.size()));
    for (const auto& c : d.add_chunks) {
        w.u64(c.size());
        w.bytes(c.data(), c.size());
    }
    w.entries(d.undo);
    w.entries(d.redo);
    w.u64(d.view.cursor);
    w.u64(d.view.anchor);
    w.u8(d.view.low_nibble);
    w.u8(d.view.ascii_focus);
    w.u64(d.view.top_row);
    w.str(d.view.parser);
    w.u64(d.view.parse_base);
    w.u64(d.view.parse_length);
    w.bookmarks(d.view.bookmarks);
    w.u8(d.dirty);
    w.u8(d.read_only);
    w.u8(d.edits_dropped);
    w.u32(uint32_t(d.backup_done.size()));
    for (const std::string& b : d.backup_done) w.str(b);
    w.u32(uint32_t(d.ref_files.size()));
    for (const PersistedDoc::RefFile& f : d.ref_files) {
        w.str(f.path);
        w.u64(f.stat.size);
        w.u64(uint64_t(f.stat.mtime_ns));
    }
    Writer x;
    x.u32(uint32_t(d.extras.size()));
    for (const auto& [k, v] : d.extras) {
        x.str(k);
        x.str(v);
    }
    w.str(x.b);
    w.u32(crc32(reinterpret_cast<const uint8_t*>(w.b.data()), w.b.size()));
    return std::move(w.b);
}

enum class Parse { Ok, Corrupt, Unsupported };

// Sessions before v4: the Parse at range was the doc extras "parse.base" / "parse.length"
// (decimal; unset = file start / to the end) and every Original piece read the document's file.
void migrate_v3(PersistedDoc& d) {
    auto take = [&](const char* key, uint64_t fallback) {
        auto it = d.extras.find(key);
        if (it == d.extras.end()) return fallback;
        char* end = nullptr;
        const unsigned long long v = std::strtoull(it->second.c_str(), &end, 10);
        const bool ok = !it->second.empty() && end && *end == 0;
        d.extras.erase(it);
        return ok ? uint64_t(v) : fallback;
    };
    d.view.parse_base = take("parse.base", 0);
    d.view.parse_length = take("parse.length", UINT64_MAX);
    auto zero = [](std::vector<Piece>& ps) {
        for (Piece& p : ps)
            if (p.src == Piece::Original) p.chunk = 0;
    };
    zero(d.pieces);
    for (auto* stack : {&d.undo, &d.redo})
        for (UndoEntry& e : *stack) zero(e.pieces);
}

// *ext_dropped: the extension block was malformed and ignored (the doc itself parsed fine).
Parse deserialize(const std::string& data, PersistedDoc& d, bool* ext_dropped) {
    *ext_dropped = false;
    if (data.size() < 12 || std::memcmp(data.data(), kMagic, 4) != 0) return Parse::Corrupt;
    const uint8_t* p = reinterpret_cast<const uint8_t*>(data.data());
    size_t body = data.size() - 4;
    Reader crc_r{p + body, 4};
    if (crc_r.u32() != crc32(p, body)) return Parse::Corrupt;  // torn or corrupted write
    // From here on the bytes are exactly what some Hexer wrote: failures mean another version.

    Reader r{p, body};
    r.pos = 4;
    r.version = r.u32();
    if (r.version < 1 || r.version > kVersion) return Parse::Unsupported;
    d.path = r.str();
    d.display_name = r.str();
    d.file_stat.exists = r.u8() != 0;
    d.file_stat.is_dir = r.u8() != 0;
    d.file_stat.size = r.u64();
    d.file_stat.mtime_ns = int64_t(r.u64());
    d.pieces = r.pieces();
    uint32_t nchunks = r.count(8);
    d.add_chunks.resize(nchunks);
    for (auto& c : d.add_chunks) {
        uint64_t len = r.u64();
        if (!r.need(size_t(std::min<uint64_t>(len, SIZE_MAX)))) break;
        c.assign(p + r.pos, p + r.pos + size_t(len));
        r.pos += size_t(len);
    }
    d.undo = r.entries();
    d.redo = r.entries();
    d.view.cursor = r.u64();
    d.view.anchor = r.u64();
    d.view.low_nibble = r.u8() != 0;
    d.view.ascii_focus = r.u8() != 0;
    d.view.top_row = r.u64();
    d.view.parser = r.str();
    if (r.version >= 4) {
        d.view.parse_base = r.u64();
        d.view.parse_length = r.u64();
    }
    d.view.bookmarks = r.bookmarks();
    d.dirty = r.u8() != 0;
    d.read_only = r.u8() != 0;
    if (r.version >= 2) {
        d.edits_dropped = r.u8() != 0;
        d.backup_done.resize(r.count(4));
        for (std::string& b : d.backup_done) b = r.str();
    } else if (r.ok && r.pos < body) {
        d.edits_dropped = r.u8() != 0;  // v1: optional trailing flag
    }
    if (r.version >= 4) {
        d.ref_files.resize(r.count(20));
        for (PersistedDoc::RefFile& f : d.ref_files) {
            f.path = r.str();
            f.stat.exists = true;
            f.stat.size = r.u64();
            f.stat.mtime_ns = int64_t(r.u64());
        }
    }
    if (r.version >= 3) {
        const uint32_t len = r.count(1);
        if (r.need(len)) {
            Reader x{p + r.pos, len};
            const uint32_t n = x.count(8);
            for (uint32_t i = 0; i < n && x.ok; ++i) {
                std::string k = x.str();
                std::string v = x.str();
                if (x.ok) d.extras[std::move(k)] = std::move(v);
            }
            if (!x.ok || x.pos != len) {
                d.extras.clear();
                *ext_dropped = true;
            }
            r.pos += len;
        }
    }
    if (r.version < 4) migrate_v3(d);
    return r.ok && r.pos == body ? Parse::Ok : Parse::Unsupported;
}

// Everything that, when unchanged, means the doc file on disk is still up to date.
std::string doc_key(const Document& doc) {
    const ViewState& v = doc.view();
    std::string k;
    k += std::to_string(doc.persist_generation()) + '|' + std::to_string(doc.state_id()) + '|' +
         std::to_string(doc.view_generation) + '|' + std::to_string(v.cursor) + '|' +
         std::to_string(v.anchor) + '|' + std::to_string(v.top_row) + '|' +
         std::to_string(int(v.low_nibble)) + std::to_string(int(v.ascii_focus)) +
         std::to_string(int(doc.read_only())) + '|' + v.parser + '|' + std::to_string(v.parse_base) + '|' +
         std::to_string(v.parse_length) + '|' + doc.path() + '|' + doc.display_name();
    return k;
}

}  // namespace


namespace {

constexpr int kMaxSlots = 16;  // main dir + instance-1..15

std::string slot_path(const std::string& base, int k) {
    return k == 0 ? base : path_join(base, "instance-" + std::to_string(k));
}

// Whole-file read without os_read_whole's 4 GiB cap (a session file holds every referenced
// pasted/preserved byte and can legitimately be that large).
bool read_session_file(const std::string& path, std::string& out, std::string* err) {
    auto f = OsFile::open(path, OsFile::Mode::Read, err);
    if (!f) return false;
    uint64_t n = f->size();
    if (n > uint64_t(SIZE_MAX / 2)) {
        if (err) *err = "too large for this build";
        return false;
    }
    try {
        out.resize(size_t(n));
    } catch (const std::bad_alloc&) {
        if (err) *err = "not enough memory to load it";
        return false;
    }
    int64_t got = n ? f->read_at(0, out.data(), size_t(n)) : 0;
    if (got < 0 || uint64_t(got) != n) {
        if (err) *err = "read error";
        return false;
    }
    return true;
}

struct Index {
    int active = 0;
    std::vector<std::string> files;
    std::vector<uint64_t> ids;  // parallel to files: Document::id() at save time, 0 = unknown
    std::map<std::string, std::string> extras;
};

// Session extras in the (line-based) index: every byte outside '!'..'~', and '%' / '=', as %XX.
std::string escape(const std::string& s) {
    static const char* hex = "0123456789ABCDEF";
    std::string o;
    for (char ch : s) {
        const unsigned char c = static_cast<unsigned char>(ch);
        if (c > ' ' && c < 0x7F && c != '%' && c != '=') {
            o += ch;
        } else {
            o += '%';
            o += hex[c >> 4];
            o += hex[c & 15];
        }
    }
    return o;
}

std::string unescape(const std::string& s) {
    auto nib = [](char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return -1;
    };
    std::string o;
    for (size_t i = 0; i < s.size(); ++i) {
        const int hi = s[i] == '%' && i + 2 < s.size() ? nib(s[i + 1]) : -1;
        const int lo = hi >= 0 ? nib(s[i + 2]) : -1;
        if (lo >= 0) {
            o += char(hi * 16 + lo);
            i += 2;
        } else {
            o += s[i];
        }
    }
    return o;
}

bool read_index(const std::string& dir, Index& idx) {
    std::string ini;
    if (!os_read_whole(path_join(dir, kIndexFile), ini)) return false;
    size_t pos = 0;
    bool last_doc = false;  // the previous line added a doc (a "docid" line belongs to it)
    while (pos < ini.size()) {
        size_t eol = ini.find('\n', pos);
        if (eol == std::string::npos) eol = ini.size();
        std::string line = ini.substr(pos, eol - pos);
        pos = eol + 1;
        while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) line.pop_back();
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = line.substr(0, eq), val = line.substr(eq + 1);
        const bool after_doc = last_doc;
        last_doc = false;
        if (key == "active") {
            idx.active = std::atoi(val.c_str());
        } else if (key == "doc") {
            // Only plain names inside the session dir.
            if (!val.empty() && val.find_first_of("/\\") == std::string::npos && val != "." && val != "..") {
                idx.files.push_back(val);
                idx.ids.push_back(0);
                last_doc = true;
            }
        } else if (key == "docid") {
            if (after_doc) idx.ids.back() = std::strtoull(val.c_str(), nullptr, 10);
        } else if (key.size() > 2 && key.compare(0, 2, "x.") == 0) {
            idx.extras[unescape(key.substr(2))] = unescape(val);
        }
    }
    return true;
}

// `ids` (parallel to the first ids.size() files, 0 = none) and `extras` are optional; older
// builds ignore their lines.
bool write_index(const std::string& dir, int active, const std::vector<std::string>& files, std::string* err,
                 const std::vector<uint64_t>& ids = {}, const std::map<std::string, std::string>& extras = {}) {
    std::string ini = "version=1\n";
    ini += "active=" + std::to_string(active) + "\n";
    for (size_t i = 0; i < files.size(); ++i) {
        ini += "doc=" + files[i] + "\n";
        if (i < ids.size() && ids[i]) ini += "docid=" + std::to_string(ids[i]) + "\n";
    }
    for (const auto& [k, v] : extras) ini += "x." + escape(k) + "=" + escape(v) + "\n";
    return os_write_whole_atomic(path_join(dir, kIndexFile), ini.data(), ini.size(), err);
}

bool same_disk_version(const FileStat& a, const FileStat& b) {
    return a.exists == b.exists && a.size == b.size && a.mtime_ns == b.mtime_ns && !os_identity_differs(a, b);
}

}  // namespace

Session::Session(std::string dir) : dir_(std::move(dir)) {}
Session::~Session() = default;

// Takes the lock of the first free slot: the main dir, or instance-<k> when other instances run.
bool Session::acquire() {
    if (lock_tried_) return !slot_dir_.empty();
    lock_tried_ = true;
    for (int k = 0; k < kMaxSlots; ++k) {
        std::string d = slot_path(dir_, k);
        if (!os_mkdirs(d)) {
            if (k == 0) {
                slot_dir_ = d;  // save() reports the error; nothing to protect yet
                return true;
            }
            continue;
        }
        bool held = false;
        auto l = OsLock::acquire(path_join(d, "lock"), &held);
        if (l || !held) {  // !held: locking unsupported here, behave as before
            lock_ = std::move(l);
            slot_dir_ = d;
            return true;
        }
    }
    return false;
}

bool Session::secondary() { return acquire() && slot_dir_ != dir_; }
bool Session::primary() { return acquire() && slot_dir_ == dir_; }

bool Session::save(const std::vector<Document*>& docs, int active_index, std::string* err) {
    if (!acquire()) {
        if (err) *err = "Too many Hexer instances are running; the session of this window is not saved";
        return false;
    }
    const std::string& dir = slot_dir_;
    if (!os_mkdirs(dir)) {
        if (err) *err = "Cannot create session directory " + dir;
        return false;
    }
    bool ok = true;
    std::string first_err;
    std::vector<Saved> next;
    std::set<std::string> names_in_use(kept_.begin(), kept_.end());
    for (const Saved& s : saved_) names_in_use.insert(s.file);

    for (Document* doc : docs) {
        if (!doc || !doc->persistable()) continue;  // process memory: pids are ephemeral, never kept
        auto it = std::find_if(saved_.begin(), saved_.end(), [&](const Saved& s) { return s.doc_id == doc->id(); });
        Saved entry;
        if (it != saved_.end())
            entry = *it;
        else
            entry.doc_id = doc->id();
        if (entry.file.empty()) {
            for (int n = 1;; ++n) {  // a name neither in use nor left over on disk
                std::string name = "doc-" + std::to_string(n) + ".hxs";
                if (!names_in_use.count(name) && !os_stat(path_join(dir, name)).exists) {
                    entry.file = name;
                    names_in_use.insert(name);
                    break;
                }
            }
        }
        std::string key = doc_key(*doc);
        std::string full = path_join(dir, entry.file);
        if (entry.view_hash != key || !os_stat(full).exists) {
            std::string e;
            FileStat disk = doc->disk_stat();
            std::string bytes = serialize(doc->persist());
            if (os_write_whole_atomic(full, bytes.data(), bytes.size(), &e)) {
                entry.view_hash = key;
                entry.state_id = doc->state_id();
                entry.disk = disk;
                entry.written = true;
            } else {
                ok = false;
                if (first_err.empty()) first_err = "Cannot write " + full + ": " + e;
                entry.view_hash.clear();  // retry next time
                if (!os_stat(full).exists) continue;  // nothing usable on disk for this doc
                // The doc was saved (or reloaded) since that file was written: replaying its old
                // pieces over the new file version would corrupt it, so drop the stale file.
                if (entry.written && !same_disk_version(entry.disk, disk)) {
                    os_remove(full);
                    continue;
                }
            }
        }
        next.push_back(entry);
    }

    std::vector<std::string> files;
    std::vector<uint64_t> ids;
    for (const Saved& s : next) {
        files.push_back(s.file);
        ids.push_back(s.doc_id);
    }
    files.insert(files.end(), kept_.begin(), kept_.end());  // never lose what we could not restore
    int active = std::clamp(active_index, 0, std::max(0, int(next.size()) - 1));
    std::string e;
    if (!write_index(dir, active, files, &e, ids, extras_)) {
        ok = false;
        if (first_err.empty()) first_err = "Cannot write session index: " + e;
    } else {
        // Only once the index no longer references them: delete files of closed docs.
        for (const std::string& f : os_list_files(dir, ".hxs")) {
            std::string name = path_filename(f);
            if (std::find(files.begin(), files.end(), name) == files.end()) os_remove(f);
        }
        for (const std::string& f : os_list_files(dir, ".hxs.tmp")) os_remove(f);  // torn writes
    }
    saved_ = std::move(next);
    if (ok) finish_adoption();  // adopted docs now live in our dir: clean up their old slots
    if (!ok && err) *err = first_err;
    return ok;
}

void Session::finish_adoption() {
    for (Adopted& a : adopted_) {
        for (const std::string& f : os_list_files(a.dir, ".hxs")) {
            std::string name = path_filename(f);
            if (std::find(a.failed.begin(), a.failed.end(), name) == a.failed.end()) os_remove(f);
        }
        if (a.failed.empty())
            os_remove(path_join(a.dir, kIndexFile));
        else
            write_index(a.dir, 0, a.failed, nullptr);  // retried by the next main instance
    }
    adopted_.clear();  // releases their locks
}

// Restores the docs listed in the index of `dir` into `out`. Returns the index in out.docs of the
// active doc of that index, or -1. Adopted docs get no file name yet (save() writes them to our dir).
int Session::load_dir(const std::string& dir, Restored& out, Adopted* adopt) {
    Index idx;
    if (!read_index(dir, idx)) return -1;
    if (!adopt) extras_ = std::move(idx.extras);  // other instances' UI state is not merged
    int restored_active = -1;
    for (size_t i = 0; i < idx.files.size(); ++i) {
        const std::string& file = idx.files[i];
        const std::string full = path_join(dir, file);
        auto keep = [&](const std::string& why) {
            out.warnings.push_back(why + "; it is kept for a later session");
            (adopt ? adopt->failed : kept_).push_back(file);
        };
        try {
            std::string data, e;
            if (!read_session_file(full, data, &e)) {
                if (!os_stat(full).exists)
                    out.warnings.push_back("Session file " + file + " is missing (skipped)");
                else
                    keep("Session file " + file + " could not be read (" + e + ")");
                continue;
            }
            PersistedDoc pd;
            bool ext_dropped = false;
            Parse parsed = deserialize(data, pd, &ext_dropped);
            data.clear();
            data.shrink_to_fit();
            if (parsed == Parse::Corrupt) {
                out.warnings.push_back("Session file " + file + " is corrupt (skipped)");
                continue;
            }
            if (parsed == Parse::Unsupported) {
                keep("Session file " + file + " was written by a different Hexer version");
                continue;
            }
            bool changed = false;
            std::string rerr, note;
            auto doc = Document::restore(pd, &changed, &rerr, &note);
            std::string name = pd.display_name.empty() ? path_filename(pd.path) : pd.display_name;
            if (!doc) {
                keep(rerr.empty() ? name + " could not be restored" : rerr);
                continue;
            }
            if (changed && pd.dirty)
                out.warnings.push_back(name + " changed on disk since last session; edits were restored on top "
                                              "of the new contents");
            if (!note.empty()) out.warnings.push_back(note);
            if (ext_dropped)
                out.warnings.push_back(name + ": its saved view state (split, parser, tail) was unreadable and was reset");
            if (pd.edits_dropped)
                out.warnings.push_back(name + ": unsaved changes that referenced a previous version of the file "
                                              "were too large to keep; the last saved version was opened");
            bool recovered = !pd.path.empty() && doc->path().empty();
            if (recovered && !(changed && pd.dirty))
                out.warnings.push_back(name + " no longer exists; its edits were restored as an untitled document");
            if (int(i) == idx.active) restored_active = int(out.docs.size());
            out.saved_ids.push_back(adopt ? 0 : idx.ids[i]);  // other processes' ids may collide
            Saved s;
            s.doc_id = doc->id();
            s.state_id = doc->state_id();
            s.file = adopt ? std::string() : file;
            s.disk = doc->disk_stat();
            s.written = !adopt;
            // Rewrite docs whose state was adjusted on restore so the warning is not repeated next time.
            s.view_hash = (changed || recovered || !note.empty() || pd.edits_dropped || ext_dropped || adopt)
                              ? std::string()
                              : doc_key(*doc);
            saved_.push_back(s);
            out.docs.push_back(std::move(doc));
        } catch (const std::bad_alloc&) {
            keep("Session file " + file + " is too large to load (out of memory)");
        }
    }
    return restored_active;
}

Session::Restored Session::load() {
    Restored out;
    saved_.clear();
    kept_.clear();
    adopted_.clear();
    extras_.clear();
    if (!acquire()) {
        out.warnings.push_back("Too many Hexer instances are running; the session of this window is not saved");
        return out;
    }
    int active = load_dir(slot_dir_, out, nullptr);
    if (slot_dir_ == dir_) {
        // Adopt the sessions of secondary instances that have exited since.
        for (int k = 1; k < kMaxSlots; ++k) {
            std::string d = slot_path(dir_, k);
            if (!os_stat(path_join(d, kIndexFile)).exists) continue;
            auto l = OsLock::acquire(path_join(d, "lock"));
            if (!l) continue;  // still running
            Adopted a;
            a.dir = d;
            a.lock = std::move(l);
            load_dir(d, out, &a);
            adopted_.push_back(std::move(a));
        }
    }
    out.active_index = out.docs.empty() ? 0 : std::clamp(std::max(active, 0), 0, int(out.docs.size()) - 1);
    return out;
}

void Session::clear() {
    if (!acquire()) return;  // not ours to delete
    for (const std::string& f : os_list_files(slot_dir_, ".hxs")) os_remove(f);
    os_remove(path_join(slot_dir_, kIndexFile));
    saved_.clear();
    kept_.clear();
    extras_.clear();
}

void Session::set_extra(const std::string& key, const std::string& value) {
    if (value.empty())
        extras_.erase(key);
    else
        extras_[key] = value;
}

std::string Session::extra(const std::string& key) const {
    auto it = extras_.find(key);
    return it == extras_.end() ? std::string() : it->second;
}

void Session::discard_kept() {
    if (!acquire()) return;
    for (const std::string& f : kept_) os_remove(path_join(slot_dir_, f));
    kept_.clear();
}

// ---- single instance inbox ----------------------------------------------------------------------

namespace {
std::string inbox_dir(const std::string& dir) { return path_join(dir, "inbox"); }
}  // namespace

bool session_primary_running(const std::string& dir) {
    bool held = false;
    auto l = OsLock::acquire(path_join(dir, "lock"), &held);
    return !l && held;  // taken by us: nobody runs (released again right here)
}

bool inbox_post(const std::string& dir, const std::vector<std::string>& files, std::string* posted,
                std::string* err) {
    const std::string in = inbox_dir(dir);
    if (!os_mkdirs(in)) {
        if (err) *err = "cannot create " + in;
        return false;
    }
    std::string text;
    for (const std::string& f : files) text += f + "\n";
    const std::string prefix = path_join(in, std::to_string(os_process_id()) + "-");
    std::string file;
    for (int n = 1;; ++n) {  // a stale file of a recycled pid must not be replaced
        file = prefix + std::to_string(n) + ".paths";
        if (!os_stat(file).exists && !os_stat(file + ".taken").exists) break;
    }
    if (!os_write_whole_atomic(file, text.data(), text.size(), err)) return false;
    if (posted) *posted = file;
    return true;
}

std::vector<std::vector<std::string>> inbox_take(const std::string& dir) {
    std::vector<std::vector<std::string>> out;
    const std::string in = inbox_dir(dir);
    // ".taken" leftovers: claimed by an instance that died before reading them.
    std::vector<std::string> claimed = os_list_files(in, ".paths.taken");
    for (const std::string& f : os_list_files(in, ".paths"))
        if (os_replace_file(f, f + ".taken")) claimed.push_back(f + ".taken");  // fails: withdrawn
    for (const std::string& f : claimed) {
        std::string text;
        const bool ok = os_read_whole(f, text);
        os_remove(f);
        if (!ok) continue;
        std::vector<std::string> paths;
        size_t pos = 0;
        while (pos < text.size()) {
            size_t eol = text.find('\n', pos);
            if (eol == std::string::npos) eol = text.size();
            std::string line = text.substr(pos, eol - pos);
            pos = eol + 1;
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (!line.empty()) paths.push_back(std::move(line));
        }
        out.push_back(std::move(paths));
    }
    return out;
}

bool inbox_withdraw(const std::string& posted) {
    // A rename fails if the running instance claimed the file first (os_remove would not tell).
    const std::string gone = posted + ".withdrawn";
    if (!os_replace_file(posted, gone)) return false;
    os_remove(gone);
    return true;
}

}  // namespace hx
