// ParseJob (script/parse_job.h): parsers on a worker thread, in a Lua state of their own.
#include <doctest/doctest.h>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <memory>
#include <random>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "core/document.h"
#include "holey_mem.h"
#include "script/parse_job.h"
#include "script/script_engine.h"

using namespace hx;
namespace fs = std::filesystem;

namespace {

struct FakeHost : ScriptHost {
    std::vector<std::unique_ptr<Document>> docs;
    Document* active = nullptr;

    Document* active_document() override { return active; }
    Document* find_document(uint64_t id) override {
        for (auto& d : docs)
            if (d->id() == id) return d.get();
        return nullptr;
    }
    Document* open_bytes(const std::string& name, const uint8_t* data, size_t len) override {
        docs.push_back(Document::create_from_bytes(name, data, len));
        active = docs.back().get();
        return active;
    }
    void reveal(Document&, uint64_t, uint64_t) override {}
    Document* add(const std::string& bytes, const std::string& name = "test.bin") {
        return open_bytes(name, reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size());
    }
};

struct TempDir {
    fs::path path;
    TempDir() {
        std::random_device rd;
        path = fs::temp_directory_path() / ("hexer_test_parsejob_" + std::to_string(rd()) + std::to_string(rd()));
        fs::create_directories(path);
    }
    ~TempDir() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
    std::string str() const {
        auto u = path.generic_u8string();
        return std::string(u.begin(), u.end());
    }
    void write(const std::string& name, const std::string& content) const {
        fs::create_directories((path / name).parent_path());
        std::ofstream out(path / name, std::ios::binary | std::ios::trunc);
        out << content;
    }
};

struct Fixture {
    FakeHost host;
    ScriptEngine eng{&host};
    TempDir dir;

    // Writes each (file, code) pair, then reloads once.
    void load(const std::vector<std::pair<std::string, std::string>>& files) {
        for (const auto& f : files) dir.write(f.first, f.second);
        eng.set_script_dirs({dir.str()});
        eng.reload();
    }
    void load(const std::string& code) { load({{"test.lua", code}}); }
    int count(const std::string& needle, int kind = -1) const {
        int n = 0;
        for (const ConsoleLine& l : eng.console())
            n += (kind < 0 || l.kind == kind) && l.text.find(needle) != std::string::npos;
        return n;
    }
    int errors() const {
        int n = 0;
        for (const ConsoleLine& l : eng.console()) n += l.kind == ConsoleLine::Error;
        return n;
    }
};

double ms_since(std::chrono::steady_clock::time_point t0) {
    return std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
}

// Same tree, field by field (what the Structure panel shows), and the same highlights.
void check_same(const ParseResult& a, const ParseResult& b) {
    CHECK(a.parser == b.parser);
    CHECK(a.error == b.error);
    CHECK(a.truncated == b.truncated);
    CHECK(a.doc_generation == b.doc_generation);
    REQUIRE(a.fields.size() == b.fields.size());
    for (size_t i = 0; i < a.fields.size(); ++i) {
        const Field &x = a.fields[i], &y = b.fields[i];
        INFO("field " << i << " " << x.name);
        CHECK(x.name == y.name);
        CHECK(x.type == y.type);
        CHECK(x.value == y.value);
        CHECK(x.comment == y.comment);
        CHECK(x.offset == y.offset);
        CHECK(x.size == y.size);
        CHECK(x.color == y.color);
        CHECK(x.parent == y.parent);
        CHECK(x.children == y.children);
        CHECK(x.pack == y.pack);
    }
    REQUIRE(a.highlights.items.size() == b.highlights.items.size());
    for (size_t i = 0; i < a.highlights.items.size(); ++i) {
        CHECK(a.highlights.items[i].offset == b.highlights.items[i].offset);
        CHECK(a.highlights.items[i].label == b.highlights.items[i].label);
    }
}

uint32_t crc32(const std::string& s) {
    uint32_t crc = 0xFFFFFFFFu;
    for (unsigned char c : s) {
        crc ^= c;
        for (int k = 0; k < 8; ++k) crc = (crc & 1) ? 0xEDB88320u ^ (crc >> 1) : crc >> 1;
    }
    return ~crc;
}

std::string be32(uint32_t v) {
    std::string s(4, '\0');
    for (int i = 0; i < 4; ++i) s[size_t(i)] = char(v >> (24 - 8 * i));
    return s;
}

const char* kSlow = R"LUA(
hx.parser { name = "slow", parse = function(p, doc)
    local t0 = os.clock()
    while os.clock() - t0 < 0.3 do end
    p:u8("first")
    p:u16be("second")
end }
)LUA";

}  // namespace

TEST_CASE("parse job: a slow parser does not block; the result arrives later") {
    Fixture fx;
    fx.load(kSlow);
    REQUIRE(fx.errors() == 0);
    Document* d = fx.host.add("\x07\x01\x02rest");
    const auto t0 = std::chrono::steady_clock::now();
    ParseJob job(fx.eng, *d, "slow");
    CHECK(ms_since(t0) < 200.0);  // the 300 ms parse runs on the worker
    CHECK(job.background());
    CHECK_FALSE(job.done());
    CHECK(job.generation() == d->generation());
    CHECK(job.wait(-1));
    CHECK(ms_since(t0) >= 250.0);
    ParseResult r = job.take(fx.eng, *d);
    INFO(r.error);
    CHECK(r.error.empty());
    CHECK(r.parser == "slow");
    CHECK(r.doc_generation == d->generation());
    REQUIRE(r.fields.size() == 2);
    CHECK(r.fields[0].name == "first");
    CHECK(r.fields[0].value == "7");
    CHECK(r.fields[1].value == "258 (0x102)");
    CHECK(r.fields[1].editable());
    CHECK(r.highlights.items.size() == 2);
    CHECK(job.fields() == 2);
    CHECK(job.offset() == 3);
}

TEST_CASE("parse job: cancel stops a runaway parser and keeps the partial tree") {
    Fixture fx;
    fx.load(R"LUA(
hx.parser { name = "spin", parse = function(p)
    p:u8("a")
    p:u8("b")
    while true do end
end }
)LUA");
    Document* d = fx.host.add("abcdef");
    ParseJob job(fx.eng, *d, "spin");
    for (int i = 0; i < 200 && job.fields() < 2; ++i) std::this_thread::sleep_for(std::chrono::milliseconds(5));
    CHECK(job.fields() == 2);  // progress while it runs
    CHECK(job.offset() == 2);
    CHECK_FALSE(job.done());
    const auto t0 = std::chrono::steady_clock::now();
    job.cancel();
    CHECK(job.wait(1500));
    CHECK(ms_since(t0) < 1000.0);  // well before the 2 s time limit
    ParseResult r = job.take(fx.eng, *d);
    CHECK(r.error == "parse cancelled");
    CHECK(r.fields.size() == 2);
    CHECK(fx.errors() == 0);  // a cancellation is not a script error

    // Destroying a running job cancels and joins it quickly as well.
    const auto t1 = std::chrono::steady_clock::now();
    {
        ParseJob again(fx.eng, *d, "spin");
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    CHECK(ms_since(t1) < 1000.0);
}

TEST_CASE("parse job: the time limit still applies") {
    Fixture fx;
    fx.load(R"LUA(
hx.parser { name = "loop", parse = function(p)
    p:u8("before")
    while true do end
end }
)LUA");
    Document* d = fx.host.add("abc");
    ParseJob job(fx.eng, *d, "loop");
    REQUIRE(job.wait(8000));
    ParseResult r = job.take(fx.eng, *d);
    CHECK(r.error.find("test.lua:4: script time limit exceeded (2000 ms)") != std::string::npos);
    CHECK(r.fields.size() == 1);
    CHECK(fx.count("time limit", ConsoleLine::Error) == 1);
}

TEST_CASE("parse job: the document is read as it was when the job started") {
    Fixture fx;
    fx.load(kSlow);
    Document* d = fx.host.add("\x07\x01\x02rest");
    const uint64_t gen = d->generation();
    ParseJob job(fx.eng, *d, "slow");
    const uint8_t x = 0x63;
    REQUIRE(d->overwrite(0, &x, 1));  // while the parser still waits
    REQUIRE(job.wait(-1));
    ParseResult r = job.take(fx.eng, *d);
    REQUIRE(r.fields.size() == 2);
    CHECK(r.fields[0].value == "7");    // the old byte
    CHECK(r.doc_generation == gen);     // stale: the UI drops it and parses again
    CHECK(r.doc_generation != d->generation());
    ParseJob again(fx.eng, *d, "slow");
    REQUIRE(again.wait(-1));
    ParseResult r2 = again.take(fx.eng, *d);
    CHECK(r2.fields[0].value == "99 (0x63)");
    CHECK(r2.doc_generation == d->generation());
}

TEST_CASE("parse job: errors carry file:line, are logged once, match a synchronous parse") {
    Fixture fx;
    fx.load({{"bad.lua", R"LUA(
hx.parser { name = "bad", parse = function(p)
    p:u8("ok")
    error("boom")
end }
)LUA"}});
    Document* d = fx.host.add("abc");
    ParseJob job(fx.eng, *d, "bad");
    REQUIRE(job.wait(-1));
    CHECK(fx.errors() == 0);  // not before take()
    ParseResult r = job.take(fx.eng, *d);
    CHECK(r.error == "bad.lua:4: boom");
    CHECK(r.fields.size() == 1);
    CHECK(fx.count("Parser 'bad': bad.lua:4: boom", ConsoleLine::Error) == 1);
    CHECK(fx.count("stack traceback", ConsoleLine::Error) == 1);
    ParseJob job2(fx.eng, *d, "bad");
    REQUIRE(job2.wait(-1));
    ParseResult r2 = job2.take(fx.eng, *d);
    CHECK(r2.error == r.error);
    CHECK(fx.count("Parser 'bad'", ConsoleLine::Error) == 1);  // once per reload, as before

    Fixture sync;
    sync.load({{"bad.lua", R"LUA(
hx.parser { name = "bad", parse = function(p)
    p:u8("ok")
    error("boom")
end }
)LUA"}});
    Document* d2 = sync.host.add("abc");
    CHECK(sync.eng.parse(*d2, "bad").error == r.error);

    // An unknown parser name: reported by the synchronous fallback.
    ParseJob unknown(fx.eng, *d, "nope");
    CHECK_FALSE(unknown.background());
    CHECK(unknown.done());
    CHECK(unknown.take(fx.eng, *d).error.find("unknown parser 'nope'") != std::string::npos);
}

TEST_CASE("parse job: print goes to the console with the result; load-time output is not repeated") {
    Fixture fx;
    fx.load(R"LUA(
print("script loaded")
hx.parser { name = "chatty", parse = function(p, doc)
    print("parsing " .. doc:name())
    hx.warn("careful")
    p:u8("id", { comment = tostring(doc:id()) .. " " .. tostring(hx.doc() == doc) })
    local ok, err = pcall(doc.write, doc, 0, "x")
    p:note(tostring(err))
end }
)LUA");
    CHECK(fx.count("script loaded") == 1);
    Document* d = fx.host.add("abc", "chat.bin");
    ParseJob job(fx.eng, *d, "chatty");
    REQUIRE(job.wait(-1));
    CHECK(fx.count("parsing chat.bin") == 0);
    ParseResult r = job.take(fx.eng, *d);
    CHECK(fx.count("parsing chat.bin", ConsoleLine::Info) == 1);
    CHECK(fx.count("careful", ConsoleLine::Warn) == 1);
    CHECK(fx.count("script loaded") == 1);
    REQUIRE(r.fields.size() == 1);
    // Same id as the real document; edits are refused (the parse reads a read-only copy).
    CHECK(r.fields[0].comment == std::to_string(d->id()) + " true; document is read-only");
    CHECK(d->generation() == r.doc_generation);
}

TEST_CASE("parse job: parse at offset, require() from lib/, run_source parsers") {
    Fixture fx;
    fx.load({{"lib/helper.lua", "return { two = function(p) p:u8('x'); p:u8('y') end }\n"},
             {"at.lua", R"LUA(
local helper = require("helper")
hx.parser { name = "at", parse = function(p)
    p:field("whole", 0, p:size(), "base " .. p:base())
    helper.two(p)
    p:u8("past")
end }
)LUA"}});
    REQUIRE(fx.errors() == 0);
    Document* d = fx.host.add("....AB...");
    ParseJob job(fx.eng, *d, "at", 4, 2);
    REQUIRE(job.background());
    REQUIRE(job.wait(-1));
    ParseResult r = job.take(fx.eng, *d);
    ParseResult s = fx.eng.parse(*d, "at", 4, 2);
    check_same(r, s);
    REQUIRE(r.fields.size() == 3);
    CHECK(r.fields[0].value == "base 4");
    CHECK(r.fields[0].size == 2);
    CHECK(r.fields[1].offset == 4);
    CHECK(r.fields[2].offset == 5);
    CHECK(r.error.find("read past end of data at 0x6") != std::string::npos);

    std::string err;
    REQUIRE(fx.eng.run_source("hx.parser { name = 'gen', parse = function(p) p:u16le('w') end }", "C struct", &err));
    ParseJob g(fx.eng, *d, "gen");
    CHECK(g.background());
    REQUIRE(g.wait(-1));
    ParseResult gr = g.take(fx.eng, *d);
    REQUIRE(gr.fields.size() == 1);
    CHECK(gr.fields[0].value == "11822 (0x2E2E)");
}

TEST_CASE("parse job: parsers that need the main state run synchronously") {
    Fixture fx;
    // Uses a global of another script at load time: does not load on its own.
    fx.load({{"a.lua", "helper_u8 = function(p, n) p:u8(n) end\n"},
             {"b.lua", "local h = assert(helper_u8)\nhx.parser { name = 'b', parse = function(p) h(p, 'h') end }\n"}});
    REQUIRE(fx.errors() == 0);
    Document* d = fx.host.add("z");
    ParseJob job(fx.eng, *d, "b");
    REQUIRE(job.wait(-1));
    CHECK_FALSE(job.background());
    ParseResult r = job.take(fx.eng, *d);
    CHECK(r.error.empty());
    REQUIRE(r.fields.size() == 1);
    CHECK(r.fields[0].name == "h");

    // Defined in the console: there is no script to rebuild it from.
    fx.eng.exec("hx.parser { name = 'con', parse = function(p) p:u8('c') end }");
    ParseJob c(fx.eng, *d, "con");
    CHECK_FALSE(c.background());
    CHECK(c.done());
    ParseResult cr = c.take(fx.eng, *d);
    REQUIRE(cr.fields.size() == 1);
    CHECK(cr.fields[0].value == "122 (0x7A)");
    CHECK(fx.errors() == 0);
}

TEST_CASE("parse job: bundled examples give the same trees as a synchronous parse") {
    FakeHost host;
    ScriptEngine eng{&host};
    eng.set_script_dirs({HEXER_SOURCE_SCRIPTS_DIR});
    eng.reload();

    std::string ihdr = std::string("\0\0\0\x10\0\0\0\x08\x08\x02\0\0\0", 13);
    std::string png = std::string("\x89PNG\r\n\x1a\n", 8);
    png += be32(13) + "IHDR" + ihdr + be32(crc32("IHDR" + ihdr));
    png += be32(0) + "IEND" + be32(crc32("IEND"));
    eng.run_command("HXP: build sample packet");
    Document* hxp = host.active;
    REQUIRE(hxp);
    eng.exec(R"LUA(
local name, data = "a.txt", "hello"
local crc = hx.crc32(data)
local lfh = string.pack("<I4I2I2I2I2I2I4I4I4I2I2", 0x04034b50, 20, 0, 0, 0, 0x21, crc, #data, #data, #name, 0) .. name .. data
local cdh = string.pack("<I4BBI2I2I2I2I2I4I4I4I2I2I2I2I2I4I4", 0x02014b50, 20, 3, 20, 0, 0, 0, 0x21, crc, #data, #data, #name, 0, 0, 0, 0, 0, 0) .. name
local eocd = string.pack("<I4I2I2I2I2I4I4I2", 0x06054b50, 0, 0, 1, 1, #cdh, #lfh, 0)
hx.new_doc("t.zip", lfh .. cdh .. eocd)
)LUA");
    Document* zip = host.active;
    REQUIRE(zip != hxp);
    Document* img = host.add(png, "img.png");
    struct Case {
        Document* doc;
        const char* parser;
    };
    for (const Case& c : {Case{img, "PNG image"}, Case{hxp, "HXP packet"}, Case{zip, "ZIP archive"}}) {
        INFO(c.parser);
        CHECK(eng.detect_parser(*c.doc) == c.parser);
        DetectJob dj(eng, *c.doc);
        CHECK(dj.background());
        CHECK(dj.take(eng, *c.doc) == c.parser);
        ParseJob job(eng, *c.doc, c.parser);
        CHECK(job.background());
        REQUIRE(job.wait(-1));
        ParseResult r = job.take(eng, *c.doc);
        INFO(r.error);
        CHECK(r.error.empty());
        CHECK(r.fields.size() > 5);
        check_same(r, eng.parse(*c.doc, c.parser));
    }
}

TEST_CASE("parse job: process memory with holes reads like a synchronous parse") {
    hx_test::HoleyMem hm;  // readable page | hole page | readable page
    for (size_t i = 0; i < 16; ++i) hm.base[i] = uint8_t(0xA0 + i);
    hm.after_ptr()[0] = 0x5A;
    FakeHost host;
    ScriptEngine eng{&host};
    std::string err;
    REQUIRE(eng.run_source("hx_pg = " + std::to_string(hm.pg) + "\n" +
                               "hx.parser { name = 'mem2', parse = function(p, doc)\n"
                               "    p:u32be('head')\n"
                               "    p:field('doc', 0, 0, doc:target() .. ' ' .. tostring(doc:pid()))\n"
                               "    p:seek(2 * hx_pg)\n"
                               "    p:u8('after')\n"
                               "    p:seek(hx_pg)\n"
                               "    p:u8('in hole')\n"
                               "end }\n",
                           "mem2", &err));
    host.docs.push_back(hx_test::open_self());
    Document* d = host.docs.back().get();
    ParseJob job(eng, *d, "mem2", hm.addr(), 3 * hm.pg);
    REQUIRE(job.background());
    REQUIRE(job.wait(-1));
    ParseResult r = job.take(eng, *d);
    ParseResult s = eng.parse(*d, "mem2", hm.addr(), 3 * hm.pg);
    // The process memory may change between the two parses only outside our pages.
    check_same(r, s);
    REQUIRE(r.fields.size() >= 3);
    CHECK(r.fields[0].value == "2694947491 (0xA0A1A2A3)");
    CHECK(r.fields[1].value == "process " + std::to_string(hx::os_process_id()));
    CHECK(r.fields[2].value == "90 (0x5A)");
    CHECK(r.fields[2].offset == hm.addr() + 2 * hm.pg);
}

// ---- DetectJob ------------------------------------------------------------------------------------

TEST_CASE("detect job: a slow detect does not block; the answer arrives later") {
    Fixture fx;
    fx.load({{"a.lua", R"LUA(
hx.parser { name = "slow", detect = function(doc)
    local t0 = os.clock()
    while os.clock() - t0 < 0.3 do end
    return false
end, parse = function(p) end }
)LUA"},
             {"b.lua", "hx.parser { name = 'seven', detect = function(doc) return doc:u8(0) == 7 end, "
                       "parse = function(p) p:u8('x') end }\n"}});
    REQUIRE(fx.errors() == 0);
    Document* d = fx.host.add("\x07rest");
    const auto t0 = std::chrono::steady_clock::now();
    DetectJob job(fx.eng, *d);
    CHECK(ms_since(t0) < 200.0);  // the 300 ms detect runs on the worker
    CHECK(job.background());
    CHECK_FALSE(job.done());
    CHECK(job.current(fx.eng, *d));
    CHECK(job.wait(-1));
    CHECK(ms_since(t0) >= 250.0);
    CHECK(job.take(fx.eng, *d) == "seven");
    CHECK(fx.eng.detect_parser(*d) == "seven");
    CHECK(fx.errors() == 0);
}

TEST_CASE("detect job: detect order, main-engine parsers in their turn, extension fallback") {
    Fixture fx;
    // "needs" uses a global of another script at load time: its detect runs in the main engine.
    fx.load({{"a.lua", "helper_one = 1\n"
                       "hx.parser { name = 'first', detect = function(doc) return doc:u8(0) == 0 end, parse = function(p) end }\n"},
             {"b.lua", "local one = assert(helper_one)\n"
                       "hx.parser { name = 'needs', detect = function(doc) return doc:u8(0) == one end, parse = function(p) end }\n"},
             {"c.lua", "hx.parser { name = 'plain', parse = function(p) end }\n"
                       "hx.parser { name = 'byext', extensions = { 'foo' }, detect = function(doc) return doc:u8(0) == 3 end, "
                       "parse = function(p) end }\n"}});
    REQUIRE(fx.errors() == 0);
    fx.eng.exec("hx.parser { name = 'con', detect = function(doc) return doc:u8(0) <= 2 end, parse = function(p) end }");
    struct Case {
        const char* bytes;
        const char* name;
        const char* want;
    };
    for (const Case& c : {Case{"\x01", "t.bin", "needs"}, Case{"\x02", "t.bin", "con"}, Case{"\x03", "t.bin", "byext"},
                          Case{"\x09", "t.foo", "byext"}, Case{"\x09", "t.bin", ""}}) {
        INFO(c.want);
        Document* d = fx.host.add(c.bytes, c.name);
        DetectJob job(fx.eng, *d);
        CHECK(job.background());
        REQUIRE(job.wait(-1));
        CHECK(job.take(fx.eng, *d) == c.want);
        CHECK(fx.eng.detect_parser(*d) == c.want);
    }
    // Byte 0: the first parser wins although later ones (con) would say yes too.
    Document* z = fx.host.add(std::string(1, '\0'));
    DetectJob job(fx.eng, *z);
    REQUIRE(job.wait(-1));
    CHECK(job.take(fx.eng, *z) == "first");
    CHECK(fx.errors() == 0);
}

TEST_CASE("detect job: stale answers are recognised; output and errors reach the console once") {
    Fixture fx;
    fx.load({{"a.lua", "hx.parser { name = 'boom', detect = function(doc) print('looking'); error('bad magic') end, "
                       "parse = function(p) end }\n"},
             {"b.lua", "hx.parser { name = 'ok', detect = function(doc) return doc:u8(0) == 0x41 end, parse = function(p) end }\n"}});
    REQUIRE(fx.errors() == 0);
    Document* d = fx.host.add("ABC");
    for (int i = 0; i < 2; ++i) {
        DetectJob job(fx.eng, *d);
        REQUIRE(job.wait(-1));
        CHECK(fx.count("looking") == i);  // buffered until take()
        CHECK(job.take(fx.eng, *d) == "ok");
        CHECK(fx.count("looking") == i + 1);
    }
    CHECK(fx.count("Parser 'boom' detect: ", ConsoleLine::Error) == 1);  // once per reload
    CHECK(fx.count("a.lua:1: bad magic", ConsoleLine::Error) == 1);

    // The answer is for the document as it was: an edit or a script reload makes it stale (the
    // Structure panel then drops it and detects again).
    DetectJob job(fx.eng, *d);
    CHECK(job.current(fx.eng, *d));
    const uint8_t x = 0x42;
    REQUIRE(d->overwrite(0, &x, 1));
    CHECK_FALSE(job.current(fx.eng, *d));
    REQUIRE(job.wait(-1));
    CHECK(job.take(fx.eng, *d) == "ok");  // what the start state said
    CHECK(fx.eng.detect_parser(*d).empty());
    DetectJob again(fx.eng, *d);
    CHECK(again.current(fx.eng, *d));
    fx.eng.reload();
    CHECK_FALSE(again.current(fx.eng, *d));
    Document* other = fx.host.add("ABC");
    CHECK_FALSE(again.current(fx.eng, *other));
}

TEST_CASE("detect job: cancel and the 1 s limit stop a runaway detect") {
    Fixture fx;
    fx.load({{"a.lua", "hx.parser { name = 'spin', detect = function(doc) while true do end end, parse = function(p) end }\n"},
             {"b.lua", "hx.parser { name = 'yes', detect = function(doc) return true end, parse = function(p) end }\n"}});
    Document* d = fx.host.add("abc");
    {
        DetectJob job(fx.eng, *d);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        CHECK_FALSE(job.done());
        const auto t0 = std::chrono::steady_clock::now();
        job.cancel();
        CHECK(job.wait(900));
        CHECK(ms_since(t0) < 800.0);
        CHECK(job.take(fx.eng, *d).empty());
        CHECK(fx.errors() == 0);  // a cancellation is not a script error
    }
    DetectJob job(fx.eng, *d);
    REQUIRE(job.wait(5000));
    CHECK(job.take(fx.eng, *d) == "yes");
    CHECK(fx.count("time limit exceeded (1000 ms)", ConsoleLine::Error) == 1);
    // Destroying a running job cancels and joins it quickly.
    const auto t1 = std::chrono::steady_clock::now();
    { DetectJob gone(fx.eng, *d); }
    CHECK(ms_since(t1) < 800.0);
}

TEST_CASE("detect job: no detect() to run in the background is done at once") {
    Fixture fx;
    fx.load("hx.parser { name = 'none', extensions = { 'bin' }, parse = function(p) end }\n");
    Document* d = fx.host.add("abc", "x.bin");
    DetectJob job(fx.eng, *d);
    CHECK_FALSE(job.background());
    CHECK(job.done());
    CHECK(job.take(fx.eng, *d) == "none");
}
