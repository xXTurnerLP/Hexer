#include "core/session.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <set>

#include "core/os_file.h"

namespace hx {

namespace {

constexpr char kMagic[4] = {'H', 'X', 'S', '1'};
constexpr uint32_t kVersion = 1;
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
        }
    }
};

struct Reader {
    const uint8_t* p;
    size_t n;
    size_t pos = 0;
    bool ok = true;

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
    w.bookmarks(d.view.bookmarks);
    w.u8(d.dirty);
    w.u8(d.read_only);
    w.u32(crc32(reinterpret_cast<const uint8_t*>(w.b.data()), w.b.size()));
    return std::move(w.b);
}

bool deserialize(const std::string& data, PersistedDoc& d) {
    if (data.size() < 12 || std::memcmp(data.data(), kMagic, 4) != 0) return false;
    const uint8_t* p = reinterpret_cast<const uint8_t*>(data.data());
    size_t body = data.size() - 4;
    Reader crc_r{p + body, 4};
    if (crc_r.u32() != crc32(p, body)) return false;  // torn or corrupted write

    Reader r{p, body};
    r.pos = 4;
    if (r.u32() != kVersion) return false;
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
    d.view.bookmarks = r.bookmarks();
    d.dirty = r.u8() != 0;
    d.read_only = r.u8() != 0;
    return r.ok && r.pos == body;
}

// Everything that, when unchanged, means the doc file on disk is still up to date.
std::string doc_key(const Document& doc) {
    const ViewState& v = doc.view();
    std::string k;
    k += std::to_string(doc.persist_generation()) + '|' + std::to_string(doc.state_id()) + '|' +
         std::to_string(doc.view_generation) + '|' + std::to_string(v.cursor) + '|' +
         std::to_string(v.anchor) + '|' + std::to_string(v.top_row) + '|' +
         std::to_string(int(v.low_nibble)) + std::to_string(int(v.ascii_focus)) +
         std::to_string(int(doc.read_only())) + '|' + v.parser + '|' + doc.path() + '|' + doc.display_name();
    return k;
}

}  // namespace

Session::Session(std::string dir) : dir_(std::move(dir)) {}

bool Session::save(const std::vector<Document*>& docs, int active_index, std::string* err) {
    if (!os_mkdirs(dir_)) {
        if (err) *err = "Cannot create session directory " + dir_;
        return false;
    }
    bool ok = true;
    std::string first_err;
    std::vector<Saved> next;
    std::set<std::string> names_in_use;
    for (const Saved& s : saved_) names_in_use.insert(s.file);

    for (Document* doc : docs) {
        if (!doc) continue;
        auto it = std::find_if(saved_.begin(), saved_.end(), [&](const Saved& s) { return s.doc_id == doc->id(); });
        Saved entry;
        if (it != saved_.end()) {
            entry = *it;
        } else {
            entry.doc_id = doc->id();
            for (int n = 1;; ++n) {  // a name neither in use nor left over on disk
                std::string name = "doc-" + std::to_string(n) + ".hxs";
                if (!names_in_use.count(name) && !os_stat(path_join(dir_, name)).exists) {
                    entry.file = name;
                    names_in_use.insert(name);
                    break;
                }
            }
        }
        std::string key = doc_key(*doc);
        std::string full = path_join(dir_, entry.file);
        if (entry.view_hash != key || !os_stat(full).exists) {
            std::string bytes = serialize(doc->persist());
            std::string e;
            if (os_write_whole_atomic(full, bytes.data(), bytes.size(), &e)) {
                entry.view_hash = key;
                entry.state_id = doc->state_id();
            } else {
                ok = false;
                if (first_err.empty()) first_err = "Cannot write " + full + ": " + e;
                entry.view_hash.clear();  // retry next time
                if (!os_stat(full).exists) continue;  // nothing usable on disk for this doc
            }
        }
        next.push_back(entry);
    }

    std::string ini = "version=1\n";
    int active = std::clamp(active_index, 0, std::max(0, int(next.size()) - 1));
    ini += "active=" + std::to_string(active) + "\n";
    for (const Saved& s : next) ini += "doc=" + s.file + "\n";
    std::string e;
    if (!os_write_whole_atomic(path_join(dir_, kIndexFile), ini.data(), ini.size(), &e)) {
        ok = false;
        if (first_err.empty()) first_err = "Cannot write session index: " + e;
    } else {
        // Only once the index no longer references them: delete files of closed docs.
        for (const std::string& f : os_list_files(dir_, ".hxs")) {
            std::string name = path_filename(f);
            bool keep = std::any_of(next.begin(), next.end(), [&](const Saved& s) { return s.file == name; });
            if (!keep) os_remove(f);
        }
        for (const std::string& f : os_list_files(dir_, ".hxs.tmp")) os_remove(f);  // torn writes
    }
    saved_ = std::move(next);
    if (!ok && err) *err = first_err;
    return ok;
}

Session::Restored Session::load() {
    Restored out;
    saved_.clear();
    std::string ini;
    if (!os_read_whole(path_join(dir_, kIndexFile), ini)) return out;

    int active = 0;
    std::vector<std::string> files;
    size_t pos = 0;
    while (pos < ini.size()) {
        size_t eol = ini.find('\n', pos);
        if (eol == std::string::npos) eol = ini.size();
        std::string line = ini.substr(pos, eol - pos);
        pos = eol + 1;
        while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) line.pop_back();
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = line.substr(0, eq), val = line.substr(eq + 1);
        if (key == "active") {
            active = std::atoi(val.c_str());
        } else if (key == "doc") {
            // Only plain names inside the session dir.
            if (!val.empty() && val.find_first_of("/\\") == std::string::npos && val != "." && val != "..")
                files.push_back(val);
        }
    }

    int restored_active = 0;
    for (size_t i = 0; i < files.size(); ++i) {
        std::string data, e;
        if (!os_read_whole(path_join(dir_, files[i]), data, &e)) {
            out.warnings.push_back("Session file " + files[i] + " is missing (skipped)");
            continue;
        }
        PersistedDoc pd;
        if (!deserialize(data, pd)) {
            out.warnings.push_back("Session file " + files[i] + " is corrupt (skipped)");
            continue;
        }
        bool changed = false;
        std::string rerr;
        auto doc = Document::restore(pd, &changed, &rerr);
        std::string name = pd.display_name.empty() ? path_filename(pd.path) : pd.display_name;
        if (!doc) {
            out.warnings.push_back(rerr.empty() ? name + " could not be restored (skipped)"
                                                : rerr + " (skipped)");
            continue;
        }
        if (changed && pd.dirty)
            out.warnings.push_back(name + " changed on disk since last session; edits were restored on top "
                                          "of the new contents");
        bool recovered = !pd.path.empty() && doc->path().empty();
        if (recovered && !(changed && pd.dirty))
            out.warnings.push_back(name + " no longer exists; its edits were restored as an untitled document");
        if (int(i) == active) restored_active = int(out.docs.size());
        Saved s;
        s.doc_id = doc->id();
        s.state_id = doc->state_id();
        s.file = files[i];
        // Rewrite docs whose state was adjusted on restore so the warning is not repeated next time.
        s.view_hash = (changed || recovered) ? std::string() : doc_key(*doc);
        saved_.push_back(s);
        out.docs.push_back(std::move(doc));
    }
    out.active_index = out.docs.empty() ? 0 : std::clamp(restored_active, 0, int(out.docs.size()) - 1);
    return out;
}

void Session::clear() {
    for (const std::string& f : os_list_files(dir_, ".hxs")) os_remove(f);
    os_remove(path_join(dir_, kIndexFile));
    saved_.clear();
}

}  // namespace hx
