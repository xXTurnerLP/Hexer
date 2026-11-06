#include "core/file_source.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <list>
#include <mutex>
#include <unordered_map>
#include <utility>
#include <vector>

#include "core/procmem.h"

namespace hx {

namespace {
constexpr size_t kBypassThreshold = 1 << 20;  // reads this large go straight to the OS (files)
constexpr uint64_t kPage = 4096;              // hole granularity of sparse sources
using Clock = std::chrono::steady_clock;
// A block that failed to read is not retried for this long: the hex view re-reads visible rows
// every frame, and each failing read of a bad sector can take seconds of kernel retries.
constexpr auto kBadRetry = std::chrono::seconds(10);
// Live targets (process memory): cached blocks are re-read after this long.
constexpr auto kLiveTtl = std::chrono::seconds(1);

struct Block {
    std::vector<uint8_t> data;
    // Sparse sources: unreadable [begin, end) ranges inside the block (zero-filled), ascending.
    std::vector<std::pair<uint32_t, uint32_t>> bad;
    Clock::time_point filled;
};

class FileBackend final : public ByteBackend {
public:
    FileBackend(std::unique_ptr<OsFile> f, bool w) : f_(std::move(f)), w_(w) {}
    uint64_t size() const override { return f_->size(); }
    size_t read(uint64_t off, uint8_t* dst, size_t n) const override {
        int64_t got = f_->read_at(off, dst, n);
        return got < 0 ? 0 : size_t(got);
    }
    bool data_range(uint64_t off, uint64_t& begin, uint64_t& end) const override {
        return f_->data_range(off, begin, end);
    }
    bool writable() const override { return w_; }
    bool write(uint64_t off, const uint8_t* src, size_t n) override { return w_ && f_->write_at(off, src, n); }
    bool flush() override { return !w_ || f_->flush(); }

private:
    std::unique_ptr<OsFile> f_;
    bool w_;
};
}  // namespace

std::unique_ptr<ByteBackend> open_file_backend(const std::string& path, bool write, std::string* err) {
    auto f = OsFile::open(path, write ? OsFile::Mode::ReadWrite : OsFile::Mode::Read, err);
    if (!f) return nullptr;
    return std::make_unique<FileBackend>(std::move(f), write);
}

struct FileSource::Impl {
    std::string path;
    FileStat stat;
    SourceKind kind = SourceKind::File;
    uint32_t pid = 0;
    bool sparse = false;                        // backend has holes (constant per source)
    std::atomic<uint64_t> size{0};              // grows only (extend())
    std::atomic<bool> io_error{false};

    mutable std::mutex mu;                      // guards everything below
    std::shared_ptr<ByteBackend> backend;       // copied out under the lock, used without it
    uint64_t epoch = 0;                         // bumped by invalidate(); stale fills are discarded
    using Lru = std::list<std::pair<uint64_t, std::shared_ptr<const Block>>>;
    Lru lru;                                    // front = most recently used
    std::unordered_map<uint64_t, Lru::iterator> map;
    std::unordered_map<uint64_t, Clock::time_point> bad;  // failed block -> earliest retry (files)

    bool live() const { return kind == SourceKind::Process; }

    void clear_cache_locked() {
        epoch++;
        lru.clear();
        map.clear();
        bad.clear();
    }

    // True if a block in [first, last] recently failed (so a large read should go block by block).
    bool any_bad(uint64_t first, uint64_t last) const {
        std::lock_guard<std::mutex> lk(mu);
        for (const auto& [index, until] : bad)
            if (index >= first && index <= last) return true;
        return false;
    }

    std::shared_ptr<ByteBackend> handle() const {
        std::lock_guard<std::mutex> lk(mu);
        return backend;
    }

    // Sparse sources: the backend's next readable offset (holes from the region map).
    uint64_t backend_next(uint64_t off) const {
        auto be = handle();
        return be ? be->next_readable(off) : size.load();
    }

    // Sparse fill: reads around the holes / failing pages, zero-filling and recording them.
    void fill_sparse(const ByteBackend& be, uint64_t off, Block& b) {
        const size_t want = b.data.size();
        size_t pos = 0;
        while (pos < want) {
            pos += be.read(off + pos, b.data.data() + pos, want - pos);
            if (pos >= want) break;
            const uint64_t at = off + pos;
            const uint64_t resume = std::max<uint64_t>(be.next_readable(at), (at / kPage + 1) * kPage);
            const size_t e = size_t(std::min<uint64_t>(resume - off, want));
            std::memset(b.data.data() + pos, 0, e - pos);
            b.bad.emplace_back(uint32_t(pos), uint32_t(e));
            pos = e;
        }
    }

    // Returns the cached or freshly read block `index` (may be short at EOF), or null on error.
    std::shared_ptr<const Block> block(uint64_t index) {
        uint64_t my_epoch;
        std::shared_ptr<ByteBackend> be;
        {
            std::lock_guard<std::mutex> lk(mu);
            auto it = map.find(index);
            if (it != map.end()) {
                if (!live() || Clock::now() - it->second->second->filled < kLiveTtl) {
                    lru.splice(lru.begin(), lru, it->second);
                    return it->second->second;
                }
                lru.erase(it->second);  // expired live block: read it again
                map.erase(it);
            }
            auto b = bad.find(index);
            if (b != bad.end()) {
                if (Clock::now() < b->second) return nullptr;  // known bad: fail fast
                bad.erase(b);
            }
            my_epoch = epoch;
            be = backend;
        }
        if (!be) {
            if (!sparse) io_error = true;
            return nullptr;
        }
        uint64_t off = index * kBlockSize;
        size_t want = size_t(std::min<uint64_t>(kBlockSize, size.load() - off));
        auto b = std::make_shared<Block>();
        b->data.resize(want);
        if (sparse) {
            fill_sparse(*be, off, *b);  // I/O outside the lock
        } else if (be->read(off, b->data.data(), want) < want) {
            io_error = true;
            std::lock_guard<std::mutex> lk(mu);
            if (epoch == my_epoch) {
                if (bad.size() >= 65536) bad.clear();
                bad[index] = Clock::now() + kBadRetry;
            }
            return nullptr;
        }
        b->filled = Clock::now();
        std::lock_guard<std::mutex> lk(mu);
        if (epoch != my_epoch) return b;  // invalidated meanwhile: use once, do not cache
        auto it = map.find(index);
        if (it != map.end()) return it->second->second;  // another thread won the race
        lru.emplace_front(index, b);
        map[index] = lru.begin();
        while (lru.size() > kMaxBlocks) {
            map.erase(lru.back().first);
            lru.pop_back();
        }
        return b;
    }
};

std::shared_ptr<FileSource> FileSource::open(const std::string& path, std::string* err) {
    auto be = open_file_backend(path, false, err);
    if (!be) return nullptr;
    std::shared_ptr<FileSource> src(new FileSource());
    src->impl_ = std::make_unique<Impl>();
    Impl& im = *src->impl_;
    im.path = path;
    im.size = be->size();
    im.stat = os_stat(path);
    im.kind = im.stat.is_device ? SourceKind::Device : SourceKind::File;
    im.backend = std::shared_ptr<ByteBackend>(std::move(be));
    return src;
}

std::shared_ptr<FileSource> FileSource::open_process(uint32_t pid, std::string* err) {
    auto be = open_process_backend(pid, false, err);
    if (!be) return nullptr;
    std::shared_ptr<FileSource> src(new FileSource());
    src->impl_ = std::make_unique<Impl>();
    Impl& im = *src->impl_;
    im.path = process_url(pid);
    im.kind = SourceKind::Process;
    im.pid = pid;
    im.sparse = be->sparse();
    im.size = be->size();
    im.stat.exists = true;
    im.stat.is_device = true;  // fixed size, no meaningful mtime, never replaced / backed up
    im.backend = std::shared_ptr<ByteBackend>(std::move(be));
    return src;
}

FileSource::~FileSource() = default;

uint64_t FileSource::size() const { return impl_->size.load(); }
const std::string& FileSource::path() const { return impl_->path; }
const FileStat& FileSource::stat_at_open() const { return impl_->stat; }
SourceKind FileSource::kind() const { return impl_->kind; }
uint32_t FileSource::pid() const { return impl_->pid; }
bool FileSource::sparse() const { return impl_->sparse; }

bool FileSource::data_range(uint64_t offset, uint64_t& begin, uint64_t& end) const {
    const Impl& im = *impl_;
    if (im.kind != SourceKind::File) return false;
    const uint64_t size = im.size.load();
    if (offset >= size) {
        begin = end = size;
        return true;
    }
    auto be = im.handle();
    uint64_t b = 0, e = 0;
    if (!be || !be->data_range(offset, b, e)) return false;
    begin = std::clamp(b, offset, size);  // the file may have grown since (live tail)
    end = std::clamp(e, begin, size);
    if (b >= size) end = begin = size;    // data only past our size: a hole up to it
    return end > begin || begin == size;
}
bool FileSource::io_error() const { return impl_->io_error.load(); }

uint64_t FileSource::epoch() const {
    std::lock_guard<std::mutex> lk(impl_->mu);
    return impl_->epoch;
}

bool FileSource::alive() const {
    auto be = impl_->handle();
    return be && be->alive();
}

bool FileSource::read_denied() const {
    auto be = impl_->handle();
    return be && be->read_denied();
}

size_t FileSource::read(uint64_t offset, uint8_t* dst, size_t len) const {
    Impl& im = *impl_;
    const uint64_t size = im.size.load();
    if (offset >= size || len == 0) return 0;
    len = size_t(std::min<uint64_t>(len, size - offset));

    if (!im.sparse && len >= kBypassThreshold &&
        !im.any_bad(offset / kBlockSize, (offset + len - 1) / kBlockSize)) {
        auto be = im.handle();
        if (be) {
            size_t got = be->read(offset, dst, len);
            if (got == len) return got;
        }
        im.io_error = true;
        // Fall through: retry block by block, so one bad sector does not fail the whole request
        // and the failing blocks get remembered.
    }

    size_t done = 0;
    while (done < len) {
        uint64_t pos = offset + done;
        if (im.sparse && im.backend_next(pos) > pos) break;  // a hole: no block to fetch
        uint64_t index = pos / kBlockSize;
        size_t in = size_t(pos % kBlockSize);
        auto b = im.block(index);
        if (!b || b->data.size() <= in) break;
        const size_t avail = std::min(len - done, b->data.size() - in);
        size_t n = avail;
        for (const auto& [s, e] : b->bad) {  // stop before the first unreadable range
            if (e <= in) continue;
            n = s <= in ? 0 : std::min<size_t>(n, s - in);
            break;
        }
        std::memcpy(dst + done, b->data.data() + in, n);
        done += n;
        if (n < avail) break;
    }
    return done;
}

uint64_t FileSource::next_readable(uint64_t offset) const {
    Impl& im = *impl_;
    const uint64_t size = im.size.load();
    if (!im.sparse || offset >= size) return std::min(offset, size);
    const uint64_t r = im.backend_next(offset);
    if (r > offset) return std::min(r, size);
    // Mapped, but maybe a page that failed to read: the block knows.
    auto b = im.block(offset / kBlockSize);
    if (!b) return offset;
    const size_t in = size_t(offset % kBlockSize);
    for (const auto& [s, e] : b->bad)
        if (s <= in && in < e) return std::min(offset - in + e, size);
    return offset;
}

uint64_t FileSource::unreadable_run(uint64_t offset, uint64_t max) const {
    if (max == 0) return 0;
    uint64_t end;
    if (!impl_->sparse) {
        end = offset + (kBlockSize - offset % kBlockSize);
    } else {
        end = next_readable(offset);
        if (end <= offset) end = (offset / kPage + 1) * kPage;
    }
    return std::min(end - offset, max);
}

bool FileSource::extend(uint64_t new_size) {
    Impl& im = *impl_;
    std::lock_guard<std::mutex> lk(im.mu);
    const uint64_t old = im.size.load();
    if (new_size < old) return false;
    if (new_size == old) return true;
    // The block holding the old EOF may be cached short: drop it (and a remembered failure of it).
    // Fills in flight sized their block by the old size: the epoch bump keeps them out of the cache.
    const uint64_t last = old / kBlockSize;
    auto it = im.map.find(last);
    if (it != im.map.end()) {
        im.lru.erase(it->second);
        im.map.erase(it);
    }
    im.bad.erase(last);
    im.epoch++;
    im.size = new_size;
    return true;
}

void FileSource::invalidate() {
    std::lock_guard<std::mutex> lk(impl_->mu);
    impl_->clear_cache_locked();
}

void FileSource::refresh() {
    auto be = impl_->handle();
    if (be) be->refresh();
    invalidate();
}

std::unique_ptr<ByteBackend> FileSource::open_writer(std::string* err) const {
    if (impl_->kind == SourceKind::Process) return open_process_backend(impl_->pid, true, err);
    return open_file_backend(impl_->path, true, err);
}

void FileSource::close_file() {
    std::lock_guard<std::mutex> lk(impl_->mu);
    impl_->clear_cache_locked();
    impl_->backend.reset();
}

bool FileSource::reopen_file(std::string* err) {
    std::unique_ptr<ByteBackend> be = impl_->kind == SourceKind::Process
                                          ? open_process_backend(impl_->pid, false, err)
                                          : open_file_backend(impl_->path, false, err);
    if (!be) return false;
    std::lock_guard<std::mutex> lk(impl_->mu);
    impl_->clear_cache_locked();
    impl_->backend = std::shared_ptr<ByteBackend>(std::move(be));
    return true;
}

}  // namespace hx
