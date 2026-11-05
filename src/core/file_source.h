#pragma once
// Read-only, block-cached random access to a file on disk. Never loads the whole file, so files of
// any size (terabytes) open instantly. Shared (shared_ptr) between a Document and its Snapshots.
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

#include "core/os_file.h"

namespace hx {

class FileSource {
public:
    static constexpr size_t kBlockSize = 64 * 1024;  // cache granularity
    static constexpr size_t kMaxBlocks = 512;        // 32 MiB LRU cache

    static std::shared_ptr<FileSource> open(const std::string& path, std::string* err = nullptr);
    ~FileSource();

    uint64_t size() const;               // size captured at open time (frozen for the piece table)
    const std::string& path() const;
    const FileStat& stat_at_open() const;

    // Thread-safe cached read. Returns bytes copied; short only at EOF or on I/O error.
    size_t read(uint64_t offset, uint8_t* dst, size_t len) const;
    void invalidate();                   // drop all cached blocks (after an in-place write)
    bool io_error() const;               // sticky: true once any read failed

    // Release / re-acquire the OS handle (Document's save fallback on filesystems that cannot
    // replace a file that is still open, e.g. FAT/exFAT/SMB). Reads fail while closed.
    void close_file();
    bool reopen_file(std::string* err = nullptr);

    struct Impl;
private:
    FileSource() = default;
    std::unique_ptr<Impl> impl_;
};

}  // namespace hx
