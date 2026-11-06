#pragma once
// Read-only, block-cached random access to a byte target: a file on disk, a raw disk / volume, or
// the address space of a running process. Never loads the whole target, so files of any size
// (terabytes) open instantly. Shared (shared_ptr) between a Document and its Snapshots.
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

#include "core/os_file.h"

namespace hx {

enum class SourceKind : uint8_t {
    File,     // regular file
    Device,   // block device / raw Windows disk or volume: fixed size, in-place writes only
    Process,  // a process's virtual address space (offset = address): fixed size, sparse, live
};

// What a FileSource reads from. Implementations must be thread-safe for concurrent read() calls.
class ByteBackend {
public:
    virtual ~ByteBackend() = default;
    virtual uint64_t size() const = 0;
    // Reads [off, off + n) into dst. Returns how many bytes from `off` on were read: n, or fewer
    // at EOF / before the first unreadable byte (the bytes after that are unspecified).
    virtual size_t read(uint64_t off, uint8_t* dst, size_t n) const = 0;
    // Sparse backends (address spaces) have holes: unmapped / inaccessible ranges that are expected
    // to be unreadable (not I/O errors). next_readable(off) is the first offset >= off that may be
    // readable (size() when none follows); off itself when off is not inside a known hole.
    virtual bool sparse() const { return false; }
    virtual uint64_t next_readable(uint64_t off) const { return off; }
    // Holes of a sparse FILE (readable, all zeros; unlike the holes above): FileSource::data_range.
    // Default: unknown (false), everything may hold data.
    virtual bool data_range(uint64_t off, uint64_t& begin, uint64_t& end) const {
        (void)off, (void)begin, (void)end;
        return false;
    }
    virtual bool writable() const { return false; }
    // Writes all n bytes at off or returns false (read-only backends always return false).
    virtual bool write(uint64_t off, const uint8_t* src, size_t n) {
        (void)off, (void)src, (void)n;
        return false;
    }
    virtual bool flush() { return true; }
    virtual void refresh() {}                      // re-query the layout (process: region map)
    virtual bool alive() const { return true; }    // false once a process target has exited
    // True when the target opened but not one of its readable regions gave a byte when probed at
    // open (process memory whose reads are refused): its view would be nothing but "??".
    virtual bool read_denied() const { return false; }
};

// A regular file / device opened through OsFile (mode Read or ReadWrite).
std::unique_ptr<ByteBackend> open_file_backend(const std::string& path, bool write, std::string* err = nullptr);

class FileSource {
public:
    static constexpr size_t kBlockSize = 64 * 1024;  // cache granularity
    static constexpr size_t kMaxBlocks = 512;        // 32 MiB LRU cache

    // A regular file or a device path ("\\.\PhysicalDrive0", "\\.\C:", "/dev/sda").
    static std::shared_ptr<FileSource> open(const std::string& path, std::string* err = nullptr);
    // The address space of process `pid` (read access; see core/procmem.h). path() is
    // "process://<pid>"; stat_at_open() is {exists, is_device} so it is treated as a fixed-size
    // target. Cached blocks expire after ~1 s so the view follows the live memory.
    static std::shared_ptr<FileSource> open_process(uint32_t pid, std::string* err = nullptr);
    ~FileSource();

    uint64_t size() const;               // size captured at open time (or by the last extend())
    const std::string& path() const;
    const FileStat& stat_at_open() const;
    SourceKind kind() const;
    uint32_t pid() const;                // Process: the process id; else 0

    // Thread-safe cached read. Returns bytes copied; short only at EOF or before an unreadable byte
    // (I/O error, or a hole of a sparse source).
    size_t read(uint64_t offset, uint8_t* dst, size_t len) const;
    // After a short read() at `offset`: how many bytes from `offset` on are unreadable (>= 1,
    // <= max). Files: up to the cache block boundary (one bad sector does not blank a whole read);
    // sparse sources: up to the end of the hole / unreadable page run.
    uint64_t unreadable_run(uint64_t offset, uint64_t max) const;
    // First offset >= offset that may be readable: offset itself unless it lies in a hole of a
    // sparse source (unmapped addresses, or pages that just failed to read); size() if none follows.
    uint64_t next_readable(uint64_t offset) const;
    bool sparse() const;                 // holes are expected (process memory)
    // Sparse files (holes that read as zeros, not the unreadable holes above): the first range at
    // or after `offset` that may hold non-zero bytes, [begin, end) with offset <= begin < end <=
    // size(); [offset, begin) is a hole. begin == end == size() when only a hole follows. False
    // when unknown (devices, process memory, no OS support): treat everything as data. One OS
    // query (FSCTL_QUERY_ALLOCATED_RANGES / SEEK_DATA + SEEK_HOLE), nothing is read.
    bool data_range(uint64_t offset, uint64_t& begin, uint64_t& end) const;
    void invalidate();                   // drop all cached blocks (after an in-place write)
    // Bumps whenever invalidate() / refresh() / extend() dropped cached bytes (the content may have
    // changed under the same source: an in-place save, a forced save, process memory).
    uint64_t epoch() const;
    // Process: re-read the region map and drop cached bytes (regions change while it runs).
    void refresh();
    bool alive() const;                  // false once a process target has exited
    bool read_denied() const;            // ByteBackend::read_denied (process memory)
    // Live tail: the file grew by appending; make [size(), new_size) readable. Only growth (false
    // if new_size < size()). Drops the cached, possibly short block at the old end. Thread-safe with
    // readers; Snapshots keep their old size (their pieces only reference the old range).
    bool extend(uint64_t new_size);
    // Sticky: true once any read failed with an I/O error. Holes of sparse sources never set it.
    bool io_error() const;

    // A separate backend for writing into this target in place (in-place save): the file / device
    // opened read-write, or the process opened with write access. size() is queried fresh.
    std::unique_ptr<ByteBackend> open_writer(std::string* err = nullptr) const;

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
