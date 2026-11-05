#include "core/file_source.h"

#include <algorithm>
#include <atomic>
#include <cstring>
#include <list>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace hx {

namespace {
constexpr size_t kBypassThreshold = 1 << 20;  // reads this large go straight to the OS
using Block = std::vector<uint8_t>;
}  // namespace

struct FileSource::Impl {
    std::string path;
    FileStat stat;
    uint64_t size = 0;
    std::atomic<bool> io_error{false};

    mutable std::mutex mu;                      // guards everything below
    std::shared_ptr<OsFile> file;               // copied out under the lock, used without it
    uint64_t epoch = 0;                         // bumped by invalidate(); stale fills are discarded
    using Lru = std::list<std::pair<uint64_t, std::shared_ptr<const Block>>>;
    Lru lru;                                    // front = most recently used
    std::unordered_map<uint64_t, Lru::iterator> map;

    std::shared_ptr<OsFile> handle() const {
        std::lock_guard<std::mutex> lk(mu);
        return file;
    }

    // Returns the cached or freshly read block `index` (may be short at EOF), or null on error.
    std::shared_ptr<const Block> block(uint64_t index) {
        uint64_t my_epoch;
        std::shared_ptr<OsFile> f;
        {
            std::lock_guard<std::mutex> lk(mu);
            auto it = map.find(index);
            if (it != map.end()) {
                lru.splice(lru.begin(), lru, it->second);
                return it->second->second;
            }
            my_epoch = epoch;
            f = file;
        }
        if (!f) {
            io_error = true;
            return nullptr;
        }
        uint64_t off = index * kBlockSize;
        size_t want = size_t(std::min<uint64_t>(kBlockSize, size - off));
        auto b = std::make_shared<Block>(want);
        int64_t got = f->read_at(off, b->data(), want);  // I/O outside the lock
        if (got < 0 || size_t(got) < want) {
            io_error = true;
            return nullptr;
        }
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
    auto f = OsFile::open(path, OsFile::Mode::Read, err);
    if (!f) return nullptr;
    std::shared_ptr<FileSource> src(new FileSource());
    src->impl_ = std::make_unique<Impl>();
    Impl& im = *src->impl_;
    im.path = path;
    im.size = f->size();
    im.stat = os_stat(path);
    im.file = std::shared_ptr<OsFile>(std::move(f));
    return src;
}

FileSource::~FileSource() = default;

uint64_t FileSource::size() const { return impl_->size; }
const std::string& FileSource::path() const { return impl_->path; }
const FileStat& FileSource::stat_at_open() const { return impl_->stat; }
bool FileSource::io_error() const { return impl_->io_error.load(); }

size_t FileSource::read(uint64_t offset, uint8_t* dst, size_t len) const {
    Impl& im = *impl_;
    if (offset >= im.size || len == 0) return 0;
    len = size_t(std::min<uint64_t>(len, im.size - offset));

    if (len >= kBypassThreshold) {
        auto f = im.handle();
        int64_t got = f ? f->read_at(offset, dst, len) : -1;
        if (got < 0) {
            im.io_error = true;
            return 0;
        }
        if (size_t(got) < len) im.io_error = true;  // file shrank under us
        return size_t(got);
    }

    size_t done = 0;
    while (done < len) {
        uint64_t pos = offset + done;
        uint64_t index = pos / kBlockSize;
        size_t in = size_t(pos % kBlockSize);
        auto b = im.block(index);
        if (!b || b->size() <= in) break;
        size_t n = std::min(len - done, b->size() - in);
        std::memcpy(dst + done, b->data() + in, n);
        done += n;
    }
    return done;
}

void FileSource::invalidate() {
    std::lock_guard<std::mutex> lk(impl_->mu);
    impl_->epoch++;
    impl_->lru.clear();
    impl_->map.clear();
}

void FileSource::close_file() {
    std::lock_guard<std::mutex> lk(impl_->mu);
    impl_->epoch++;
    impl_->lru.clear();
    impl_->map.clear();
    impl_->file.reset();
}

bool FileSource::reopen_file(std::string* err) {
    auto f = OsFile::open(impl_->path, OsFile::Mode::Read, err);
    if (!f) return false;
    std::lock_guard<std::mutex> lk(impl_->mu);
    impl_->epoch++;
    impl_->lru.clear();
    impl_->map.clear();
    impl_->file = std::shared_ptr<OsFile>(std::move(f));
    return true;
}

}  // namespace hx
