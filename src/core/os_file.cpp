#ifndef _WIN32
#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif
#endif

#include "core/os_file.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <filesystem>
#include <system_error>

#ifdef _WIN32
#include <windows.h>
#include <shellapi.h>
#include <winioctl.h>
#else
#include <cerrno>
#include <cstdlib>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif
#endif

namespace fs = std::filesystem;

namespace hx {

namespace {

void set_err(std::string* err, const std::string& msg) {
    if (err) *err = msg;
}

#ifdef _WIN32
std::string win_error(DWORD code) {
    wchar_t* buf = nullptr;
    DWORD n = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                                 FORMAT_MESSAGE_IGNORE_INSERTS,
                             nullptr, code, 0, reinterpret_cast<wchar_t*>(&buf), 0, nullptr);
    std::string msg;
    if (n && buf) {
        msg = wide_to_utf8(std::wstring(buf, n));
        while (!msg.empty() && (msg.back() == '\n' || msg.back() == '\r' || msg.back() == ' ' ||
                                msg.back() == '.'))
            msg.pop_back();
    }
    if (buf) LocalFree(buf);
    if (msg.empty()) msg = "error " + std::to_string(code);
    return msg;
}

// UTF-8 path -> wide path usable by Win32 APIs. Long absolute paths get the \\?\ prefix so they
// are not limited to MAX_PATH (that prefix disables '/' normalisation, so normalise first).
std::wstring win_path(const std::string& p) {
    std::wstring w = utf8_to_wide(p);
    if (w.size() < 240) return w;
    if (w.rfind(L"\\\\?\\", 0) == 0) return w;
    std::replace(w.begin(), w.end(), L'/', L'\\');
    if (w.size() >= 3 && w[1] == L':' && w[2] == L'\\') return L"\\\\?\\" + w;
    if (w.size() >= 2 && w[0] == L'\\' && w[1] == L'\\') return L"\\\\?\\UNC\\" + w.substr(2);
    return w;
}

HANDLE as_handle(intptr_t h) { return reinterpret_cast<HANDLE>(h); }
#else
std::string posix_error(int e) { return std::strerror(e); }
#endif

fs::path to_fs(const std::string& s) {
#ifdef _WIN32
    return fs::path(utf8_to_wide(s));
#else
    return fs::path(s);
#endif
}

std::string from_fs(const fs::path& p) {
#ifdef _WIN32
    return wide_to_utf8(p.wstring());
#else
    return p.string();
#endif
}

bool is_sep(char c) {
#ifdef _WIN32
    return c == '/' || c == '\\';
#else
    return c == '/';
#endif
}

std::string lower_ascii(std::string s) {
    for (char& c : s) c = char(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

}  // namespace

// ---------------------------------------------------------------------------------------------
// UTF-8 <-> UTF-16
// ---------------------------------------------------------------------------------------------
#ifdef _WIN32
std::wstring utf8_to_wide(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), int(s.size()), nullptr, 0);
    if (n <= 0) return {};
    std::wstring w(size_t(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), int(s.size()), w.data(), n);
    return w;
}

std::string wide_to_utf8(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), int(w.size()), nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string s(size_t(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), int(w.size()), s.data(), n, nullptr, nullptr);
    return s;
}
#endif

// ---------------------------------------------------------------------------------------------
// OsFile
// ---------------------------------------------------------------------------------------------
#ifdef _WIN32

std::unique_ptr<OsFile> OsFile::open(const std::string& path, Mode mode, std::string* err) {
    DWORD access = GENERIC_READ;
    DWORD disposition = OPEN_EXISTING;
    if (mode == Mode::ReadWrite) access |= GENERIC_WRITE;
    if (mode == Mode::CreateTruncate) {
        access |= GENERIC_WRITE;
        disposition = CREATE_ALWAYS;
    }
    HANDLE h = CreateFileW(win_path(path).c_str(), access,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                           disposition, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        set_err(err, win_error(GetLastError()));
        return nullptr;
    }
    std::unique_ptr<OsFile> f(new OsFile());
    f->h_ = reinterpret_cast<intptr_t>(h);
    return f;
}

OsFile::~OsFile() {
    if (h_ != -1) CloseHandle(as_handle(h_));
}

uint64_t OsFile::size() const {
    LARGE_INTEGER li{};
    if (GetFileSizeEx(as_handle(h_), &li)) return uint64_t(li.QuadPart);
    // Raw disks / volumes (\\.\PhysicalDrive0) do not support GetFileSizeEx.
    GET_LENGTH_INFORMATION gli{};
    DWORD got = 0;
    if (DeviceIoControl(as_handle(h_), IOCTL_DISK_GET_LENGTH_INFO, nullptr, 0, &gli, sizeof(gli),
                        &got, nullptr))
        return uint64_t(gli.Length.QuadPart);
    return 0;
}

int64_t OsFile::read_at(uint64_t offset, void* dst, size_t len) const {
    uint8_t* out = static_cast<uint8_t*>(dst);
    size_t done = 0;
    while (done < len) {
        DWORD chunk = DWORD(std::min<size_t>(len - done, 0x40000000u));  // 1 GiB per call
        OVERLAPPED ov{};
        uint64_t pos = offset + done;
        ov.Offset = DWORD(pos & 0xFFFFFFFFu);
        ov.OffsetHigh = DWORD(pos >> 32);
        DWORD got = 0;
        if (!ReadFile(as_handle(h_), out + done, chunk, &got, &ov)) {
            DWORD e = GetLastError();
            if (e == ERROR_HANDLE_EOF) break;
            return -1;
        }
        if (got == 0) break;
        done += got;
    }
    return int64_t(done);
}

bool OsFile::write_at(uint64_t offset, const void* src, size_t len) {
    const uint8_t* in = static_cast<const uint8_t*>(src);
    size_t done = 0;
    while (done < len) {
        DWORD chunk = DWORD(std::min<size_t>(len - done, 0x40000000u));
        OVERLAPPED ov{};
        uint64_t pos = offset + done;
        ov.Offset = DWORD(pos & 0xFFFFFFFFu);
        ov.OffsetHigh = DWORD(pos >> 32);
        DWORD put = 0;
        if (!WriteFile(as_handle(h_), in + done, chunk, &put, &ov) || put == 0) return false;
        done += put;
    }
    return true;
}

bool OsFile::truncate(uint64_t new_size) {
    FILE_END_OF_FILE_INFO info{};
    info.EndOfFile.QuadPart = LONGLONG(new_size);
    if (SetFileInformationByHandle(as_handle(h_), FileEndOfFileInfo, &info, sizeof(info))) return true;
    LARGE_INTEGER li{};
    li.QuadPart = LONGLONG(new_size);
    return SetFilePointerEx(as_handle(h_), li, nullptr, FILE_BEGIN) && SetEndOfFile(as_handle(h_));
}

bool OsFile::flush() { return FlushFileBuffers(as_handle(h_)) != 0; }

#else  // POSIX

std::unique_ptr<OsFile> OsFile::open(const std::string& path, Mode mode, std::string* err) {
    int flags = O_CLOEXEC;
    if (mode == Mode::Read) flags |= O_RDONLY;
    if (mode == Mode::ReadWrite) flags |= O_RDWR;
    if (mode == Mode::CreateTruncate) flags |= O_RDWR | O_CREAT | O_TRUNC;
    int fd;
    do {
        fd = ::open(path.c_str(), flags, 0666);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0) {
        set_err(err, posix_error(errno));
        return nullptr;
    }
    struct stat st {};
    if (fstat(fd, &st) == 0 && S_ISDIR(st.st_mode)) {
        ::close(fd);
        set_err(err, posix_error(EISDIR));
        return nullptr;
    }
    std::unique_ptr<OsFile> f(new OsFile());
    f->h_ = fd;
    return f;
}

OsFile::~OsFile() {
    if (h_ != -1) ::close(int(h_));
}

uint64_t OsFile::size() const {
    struct stat st {};
    if (fstat(int(h_), &st) != 0) return 0;
    if (S_ISREG(st.st_mode)) return uint64_t(st.st_size);
    // Block devices report st_size 0; seeking to the end works for them (we only use pread, so
    // moving the file offset is harmless).
    off_t end = lseek(int(h_), 0, SEEK_END);
    return end > 0 ? uint64_t(end) : 0;
}

int64_t OsFile::read_at(uint64_t offset, void* dst, size_t len) const {
    uint8_t* out = static_cast<uint8_t*>(dst);
    size_t done = 0;
    while (done < len) {
        size_t chunk = std::min<size_t>(len - done, size_t(1) << 30);
        ssize_t r = ::pread(int(h_), out + done, chunk, off_t(offset + done));
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) break;
        done += size_t(r);
    }
    return int64_t(done);
}

bool OsFile::write_at(uint64_t offset, const void* src, size_t len) {
    const uint8_t* in = static_cast<const uint8_t*>(src);
    size_t done = 0;
    while (done < len) {
        size_t chunk = std::min<size_t>(len - done, size_t(1) << 30);
        ssize_t r = ::pwrite(int(h_), in + done, chunk, off_t(offset + done));
        if (r < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (r == 0) return false;
        done += size_t(r);
    }
    return true;
}

bool OsFile::truncate(uint64_t new_size) {
    int r;
    do {
        r = ::ftruncate(int(h_), off_t(new_size));
    } while (r != 0 && errno == EINTR);
    return r == 0;
}

bool OsFile::flush() {
    int r;
    do {
        r = ::fsync(int(h_));
    } while (r != 0 && errno == EINTR);
    return r == 0;
}

#endif

// ---------------------------------------------------------------------------------------------
// Filesystem helpers
// ---------------------------------------------------------------------------------------------
FileStat os_stat(const std::string& path) {
    FileStat st;
#ifdef _WIN32
    WIN32_FILE_ATTRIBUTE_DATA data{};
    if (!GetFileAttributesExW(win_path(path).c_str(), GetFileExInfoStandard, &data)) return st;
    st.exists = true;
    st.is_dir = (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    st.size = (uint64_t(data.nFileSizeHigh) << 32) | data.nFileSizeLow;
    int64_t ft = int64_t((uint64_t(data.ftLastWriteTime.dwHighDateTime) << 32) |
                         data.ftLastWriteTime.dwLowDateTime);
    st.mtime_ns = (ft - 116444736000000000LL) * 100;  // 100 ns ticks since 1601 -> ns since 1970
#else
    struct stat s {};
    if (::stat(path.c_str(), &s) != 0) return st;
    st.exists = true;
    st.is_dir = S_ISDIR(s.st_mode);
    st.size = uint64_t(s.st_size);
#ifdef __APPLE__
    st.mtime_ns = int64_t(s.st_mtimespec.tv_sec) * 1000000000LL + s.st_mtimespec.tv_nsec;
#else
    st.mtime_ns = int64_t(s.st_mtim.tv_sec) * 1000000000LL + s.st_mtim.tv_nsec;
#endif
#endif
    return st;
}

bool os_replace_file(const std::string& src, const std::string& dst, std::string* err) {
#ifdef _WIN32
    std::wstring wsrc = win_path(src);
    // Full path of the target for FILE_RENAME_INFO (relative names are not allowed there).
    std::wstring wdst = utf8_to_wide(dst);
    {
        DWORD n = GetFullPathNameW(wdst.c_str(), 0, nullptr, nullptr);
        if (n) {
            std::wstring full(n, L'\0');
            DWORD m = GetFullPathNameW(wdst.c_str(), n, full.data(), nullptr);
            if (m && m < n) {
                full.resize(m);
                wdst = full;
            }
        }
    }

    // Antivirus / indexers briefly opening the fresh file cause sharing violations: retry a little.
    DWORD last = 0;
    for (int attempt = 0; attempt < 8; ++attempt) {
        if (attempt) Sleep(25);
        // Preferred: POSIX-semantics rename on a handle of src. Existing handles to the replaced file
        // (our FileSource of the previous version) stay valid and keep reading the old bytes.
        HANDLE h = CreateFileW(wsrc.c_str(), DELETE | SYNCHRONIZE,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            // Layout of FILE_RENAME_INFO with the Win10 RS1 Flags union (declared locally so we do not
            // depend on SDK version macros).
            struct RenameInfoEx {
                DWORD Flags;
                HANDLE RootDirectory;
                DWORD FileNameLength;
                WCHAR FileName[1];
            };
            const DWORD kReplaceIfExists = 0x00000001;  // FILE_RENAME_FLAG_REPLACE_IF_EXISTS
            const DWORD kPosixSemantics = 0x00000002;   // FILE_RENAME_FLAG_POSIX_SEMANTICS
            const int kFileRenameInfoEx = 22;           // FILE_INFO_BY_HANDLE_CLASS::FileRenameInfoEx
            size_t bytes = sizeof(RenameInfoEx) + wdst.size() * sizeof(WCHAR);
            std::vector<uint8_t> buf(bytes, 0);
            auto* info = reinterpret_cast<RenameInfoEx*>(buf.data());
            info->Flags = kReplaceIfExists | kPosixSemantics;
            info->RootDirectory = nullptr;
            info->FileNameLength = DWORD(wdst.size() * sizeof(WCHAR));
            std::memcpy(info->FileName, wdst.data(), wdst.size() * sizeof(WCHAR));
            BOOL ok = SetFileInformationByHandle(h, FILE_INFO_BY_HANDLE_CLASS(kFileRenameInfoEx), info,
                                                 DWORD(bytes));
            CloseHandle(h);
            if (ok) return true;
        }
        // Fallback (FAT/exFAT, network shares, older Windows): classic replace.
        if (MoveFileExW(wsrc.c_str(), win_path(dst).c_str(),
                        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
            return true;
        last = GetLastError();
        if (last != ERROR_SHARING_VIOLATION && last != ERROR_ACCESS_DENIED && last != ERROR_LOCK_VIOLATION) break;
    }
    set_err(err, win_error(last));
    return false;
#else
    if (::rename(src.c_str(), dst.c_str()) == 0) {
        // Make the rename durable: fsync the containing directory (best effort).
        std::string dir = path_dirname(dst);
        if (dir.empty()) dir = ".";
        int fd = ::open(dir.c_str(), O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            ::fsync(fd);
            ::close(fd);
        }
        return true;
    }
    set_err(err, posix_error(errno));
    return false;
#endif
}

bool os_remove(const std::string& path) {
#ifdef _WIN32
    if (DeleteFileW(win_path(path).c_str())) return true;
    DWORD e = GetLastError();
    return e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND;
#else
    return ::unlink(path.c_str()) == 0 || errno == ENOENT;
#endif
}

bool os_mkdirs(const std::string& path) {
    if (path.empty()) return false;
    std::error_code ec;
    fs::path p = to_fs(path);
    fs::create_directories(p, ec);
    return fs::is_directory(p, ec);
}

std::vector<std::string> os_list_files(const std::string& dir, const std::string& ext) {
    std::vector<std::string> out;
    std::error_code ec;
    std::string lext = lower_ascii(ext);
    fs::directory_iterator it(to_fs(dir), ec), end;
    for (; !ec && it != end; it.increment(ec)) {
        std::error_code ec2;
        if (!it->is_regular_file(ec2)) continue;
        std::string name = from_fs(it->path().filename());
        std::string lname = lower_ascii(name);
        if (lext.size() > lname.size() || lname.compare(lname.size() - lext.size(), lext.size(), lext) != 0)
            continue;
        out.push_back(path_join(dir, name));
    }
    std::sort(out.begin(), out.end(),
              [](const std::string& a, const std::string& b) { return path_filename(a) < path_filename(b); });
    return out;
}

std::string os_exe_dir() {
#ifdef _WIN32
    std::wstring buf(MAX_PATH, L'\0');
    for (;;) {
        DWORD n = GetModuleFileNameW(nullptr, buf.data(), DWORD(buf.size()));
        if (n == 0) return {};
        if (n < buf.size()) {
            buf.resize(n);
            break;
        }
        buf.resize(buf.size() * 2);
        if (buf.size() > 32768 * 2) return {};
    }
    return path_dirname(wide_to_utf8(buf));
#elif defined(__APPLE__)
    uint32_t n = 0;
    _NSGetExecutablePath(nullptr, &n);
    std::string buf(n, '\0');
    if (_NSGetExecutablePath(buf.data(), &n) != 0) return {};
    buf.resize(std::strlen(buf.c_str()));
    std::error_code ec;
    fs::path p = fs::canonical(buf, ec);
    return path_dirname(ec ? buf : p.string());
#else
    std::string buf(4096, '\0');
    ssize_t n = ::readlink("/proc/self/exe", buf.data(), buf.size());
    if (n <= 0 || size_t(n) >= buf.size()) return {};
    buf.resize(size_t(n));
    return path_dirname(buf);
#endif
}

std::string os_env(const char* name) {
#ifdef _WIN32
    std::wstring wname = utf8_to_wide(name);
    DWORD n = GetEnvironmentVariableW(wname.c_str(), nullptr, 0);
    if (n == 0) return {};
    std::wstring buf(n, L'\0');
    DWORD m = GetEnvironmentVariableW(wname.c_str(), buf.data(), n);
    if (m == 0 || m >= n) return {};
    buf.resize(m);
    return wide_to_utf8(buf);
#else
    const char* v = std::getenv(name);
    return v ? std::string(v) : std::string();
#endif
}

void os_reveal_in_file_manager(const std::string& path) {
    FileStat st = os_stat(path);
#ifdef _WIN32
    std::wstring w = utf8_to_wide(path);
    std::replace(w.begin(), w.end(), L'/', L'\\');
    if (st.exists && !st.is_dir) {
        // Paths cannot contain '"', so quoting is injection-safe.
        std::wstring args = L"/select,\"" + w + L"\"";
        ShellExecuteW(nullptr, L"open", L"explorer.exe", args.c_str(), nullptr, SW_SHOWNORMAL);
    } else {
        ShellExecuteW(nullptr, L"open", w.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
    }
#else
    std::string dir = (st.exists && st.is_dir) ? path : path_dirname(path);
    if (dir.empty()) dir = ".";
#ifdef __APPLE__
    const char* tool = "open";
#else
    const char* tool = "xdg-open";
#endif
    // Double fork so the opener is reparented to init and never becomes a zombie; exec directly
    // (no shell) so the path cannot inject commands.
    pid_t pid = fork();
    if (pid == 0) {
        pid_t pid2 = fork();
        if (pid2 == 0) {
            setsid();
            execlp(tool, tool, dir.c_str(), static_cast<char*>(nullptr));
            _exit(127);
        }
        _exit(0);
    } else if (pid > 0) {
        int status = 0;
        while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
        }
    }
#endif
}

bool os_read_whole(const std::string& path, std::string& out, std::string* err) {
    auto f = OsFile::open(path, OsFile::Mode::Read, err);
    if (!f) return false;
    uint64_t n = f->size();
    if (n > (uint64_t(1) << 32)) {
        set_err(err, "file too large");
        return false;
    }
    out.resize(size_t(n));
    int64_t got = n ? f->read_at(0, out.data(), size_t(n)) : 0;
    if (got < 0) {
        set_err(err, "read error");
        return false;
    }
    out.resize(size_t(got));
    return true;
}

bool os_write_whole_atomic(const std::string& path, const void* data, size_t len, std::string* err) {
    std::string tmp = path + ".tmp";
    {
        auto f = OsFile::open(tmp, OsFile::Mode::CreateTruncate, err);
        if (!f) return false;
        if ((len && !f->write_at(0, data, len)) || !f->flush()) {
            set_err(err, "write failed: " + tmp);
            f.reset();
            os_remove(tmp);
            return false;
        }
    }
    if (!os_replace_file(tmp, path, err)) {
        os_remove(tmp);
        return false;
    }
    return true;
}

bool os_same_file(const std::string& a, const std::string& b) {
    if (a.empty() || b.empty()) return false;
    std::error_code ec;
    bool same = fs::equivalent(to_fs(a), to_fs(b), ec);
    return !ec && same;
}

std::string os_absolute_path(const std::string& p) {
    if (p.empty()) return p;
#ifdef _WIN32
    // Device / verbatim paths ("\\.\PhysicalDrive0", "\\?\C:\dir") must not be normalised.
    if (p.size() >= 4 && is_sep(p[0]) && is_sep(p[1]) && (p[2] == '.' || p[2] == '?') && is_sep(p[3])) return p;
#endif
    std::error_code ec;
    fs::path abs = fs::absolute(to_fs(p), ec);
    if (ec) return p;
    return from_fs(abs.lexically_normal());
}

bool os_copy_permissions(const std::string& from, const std::string& to) {
#ifdef _WIN32
    (void)from;
    (void)to;
    return true;  // new files inherit the directory ACL; nothing portable to copy
#else
    struct stat s {};
    if (::stat(from.c_str(), &s) != 0) return false;
    return ::chmod(to.c_str(), s.st_mode & 07777) == 0;
#endif
}

// ---------------------------------------------------------------------------------------------
// Path helpers (both separators accepted on Windows)
// ---------------------------------------------------------------------------------------------
std::string path_join(const std::string& a, const std::string& b) {
    if (a.empty()) return b;
    if (b.empty()) return a;
    if (is_sep(a.back())) return a + b;
#ifdef _WIN32
    char sep = a.find('/') != std::string::npos && a.find('\\') == std::string::npos ? '/' : '\\';
#else
    char sep = '/';
#endif
    return a + sep + b;
}

std::string path_filename(const std::string& p) {
    size_t i = p.size();
    while (i > 0 && !is_sep(p[i - 1])) --i;
#ifdef _WIN32
    if (i == 0 && p.size() >= 2 && p[1] == ':') return p.substr(2);
#endif
    return p.substr(i);
}

std::string path_dirname(const std::string& p) {
    size_t i = p.size();
    while (i > 0 && !is_sep(p[i - 1])) --i;
    if (i == 0) {
#ifdef _WIN32
        if (p.size() >= 2 && p[1] == ':') return p.substr(0, 2);
#endif
        return {};
    }
    size_t end = i - 1;                                  // position of the separator
    while (end > 0 && is_sep(p[end - 1])) --end;         // collapse "a//b"
    if (end == 0) return p.substr(0, 1);                 // "/x" -> "/"
#ifdef _WIN32
    if (end == 2 && p[1] == ':') return p.substr(0, 3);  // "c:/x" -> "c:/"
#endif
    return p.substr(0, end);
}

std::string path_extension(const std::string& p) {
    std::string name = path_filename(p);
    size_t dot = name.rfind('.');
    if (dot == std::string::npos || dot == 0) return {};
    return lower_ascii(name.substr(dot + 1));
}

}  // namespace hx
