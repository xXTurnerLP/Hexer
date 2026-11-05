#pragma once
// Thin cross-platform OS layer: positional file I/O + a few filesystem helpers.
// All paths are UTF-8; converted to UTF-16 internally on Windows.
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace hx {

// File handle using positional I/O only (pread/pwrite, ReadFile/WriteFile with OVERLAPPED offsets),
// so concurrent read_at() calls from several threads are safe.
// On Windows files are opened with FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE so that
// a file we are viewing can still be written in place / replaced by our own save code.
class OsFile {
public:
    enum class Mode { Read, ReadWrite, CreateTruncate };
    static std::unique_ptr<OsFile> open(const std::string& path, Mode mode, std::string* err = nullptr);
    ~OsFile();
    OsFile(const OsFile&) = delete;
    OsFile& operator=(const OsFile&) = delete;

    uint64_t size() const;                                          // queried from the OS each call
    int64_t read_at(uint64_t offset, void* dst, size_t len) const;  // bytes read (< len only at EOF), -1 on error
    bool write_at(uint64_t offset, const void* src, size_t len);    // writes all bytes or returns false
    bool truncate(uint64_t new_size);
    bool flush();                                                   // fsync / FlushFileBuffers

private:
    OsFile() = default;
    intptr_t h_ = -1;  // HANDLE on Windows, fd on POSIX
};

struct FileStat {
    bool exists = false;
    bool is_dir = false;
    uint64_t size = 0;
    int64_t mtime_ns = 0;
};

FileStat os_stat(const std::string& path);
// Atomically replace `dst` with `src` (src disappears). Must work while `dst` is open by this process
// with share-delete semantics. Windows: POSIX-semantics rename (FileRenameInfoEx) so existing handles
// to the old dst keep reading the old bytes; falls back to MoveFileExW REPLACE_EXISTING|WRITE_THROUGH
// (FAT/exFAT/SMB). POSIX: rename + fsync of the directory.
bool os_replace_file(const std::string& src, const std::string& dst, std::string* err = nullptr);
bool os_remove(const std::string& path);
bool os_mkdirs(const std::string& path);  // like mkdir -p; true if it exists afterwards
// Non-recursive listing of regular files whose name ends with `ext` (e.g. ".lua", case-insensitive).
// Returns full paths sorted by name.
std::vector<std::string> os_list_files(const std::string& dir, const std::string& ext);
std::string os_exe_dir();
std::string os_env(const char* name);                     // "" if unset
void os_reveal_in_file_manager(const std::string& path);  // opens the folder (Explorer / xdg-open)
// Small-file helpers (scripts, settings, session index). Not for user data files.
bool os_read_whole(const std::string& path, std::string& out, std::string* err = nullptr);
bool os_write_whole_atomic(const std::string& path, const void* data, size_t len, std::string* err = nullptr);
bool os_same_file(const std::string& a, const std::string& b);  // both exist and are the same file
std::string os_absolute_path(const std::string& p);            // absolute + lexically normalised
// POSIX: copy permission bits from `from` to `to` (used when a save replaces a file). Windows: no-op.
bool os_copy_permissions(const std::string& from, const std::string& to);

std::string path_join(const std::string& a, const std::string& b);
std::string path_filename(const std::string& p);   // "c:/x/y.bin" -> "y.bin"
std::string path_dirname(const std::string& p);    // "c:/x/y.bin" -> "c:/x"
std::string path_extension(const std::string& p);  // lowercase, no dot: "y.BIN" -> "bin"

#ifdef _WIN32
std::wstring utf8_to_wide(const std::string& s);
std::string wide_to_utf8(const std::wstring& s);
#endif

}  // namespace hx
