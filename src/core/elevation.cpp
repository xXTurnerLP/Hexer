#include "core/elevation.h"

#include <chrono>
#include <mutex>
#include <thread>
#include <utility>

#include "core/os_file.h"

#ifdef _WIN32
#include <windows.h>
#include <shellapi.h>
#else
#include <cerrno>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace hx {

namespace {
std::mutex g_launcher_mu;
ElevatedLauncher g_launcher;  // tests (set_elevated_launcher); empty = the OS launch

#ifdef _WIN32
std::wstring exe_path_w() {
    std::wstring buf(MAX_PATH, L'\0');
    for (;;) {
        const DWORD n = GetModuleFileNameW(nullptr, buf.data(), DWORD(buf.size()));
        if (n == 0) return {};
        if (n < buf.size()) {
            buf.resize(n);
            return buf;
        }
        if (buf.size() >= 32768) return {};
        buf.resize(buf.size() * 2);
    }
}

bool os_launch(const std::vector<std::string>& args, std::string* err, bool* cancelled) {
    const std::wstring exe = exe_path_w();
    if (exe.empty()) {
        if (err) *err = "cannot find the Hexer executable";
        return false;
    }
    const std::string verb_env = os_env("HEXER_TEST_RESTART_VERB");
    const std::wstring verb = utf8_to_wide(verb_env.empty() ? std::string("runas") : verb_env);
    const std::wstring params = utf8_to_wide(win_command_line(args));
    SHELLEXECUTEINFOW sei{};
    sei.cbSize = sizeof sei;
    sei.fMask = SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI | SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = verb.c_str();
    sei.lpFile = exe.c_str();
    sei.lpParameters = params.c_str();
    sei.nShow = SW_SHOWNORMAL;
    if (!ShellExecuteExW(&sei)) {
        const DWORD e = GetLastError();
        if (e == ERROR_CANCELLED) {
            if (cancelled) *cancelled = true;
            if (err) *err = "the administrator prompt was cancelled";
        } else if (err) {
            *err = "cannot start Hexer as administrator (error " + std::to_string(e) + ")";
        }
        return false;
    }
    if (sei.hProcess) {
        AllowSetForegroundWindow(GetProcessId(sei.hProcess));  // its window may take the focus
        CloseHandle(sei.hProcess);
    }
    return true;
}
#else
bool os_launch(const std::vector<std::string>&, std::string* err, bool*) {
    if (err) *err = "restarting as administrator is only supported on Windows (run Hexer as root instead)";
    return false;
}
#endif
}  // namespace

bool os_elevated() {
    // Fixed for the life of the process: asked once (menus and the title ask every frame).
    static const bool elevated = [] {
#ifdef _WIN32
        HANDLE tok = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return false;
        TOKEN_ELEVATION e{};
        DWORD n = 0;
        const bool ok = GetTokenInformation(tok, TokenElevation, &e, sizeof e, &n) && e.TokenIsElevated;
        CloseHandle(tok);
        return ok;
#else
        return ::geteuid() == 0;
#endif
    }();
    return elevated;
}

bool can_restart_elevated() {
#ifdef _WIN32
    return !os_elevated();
#else
    return false;
#endif
}

std::string win_quote_arg(const std::string& arg) {
    if (!arg.empty() && arg.find_first_of(" \t\n\v\"") == std::string::npos) return arg;
    std::string out = "\"";
    size_t slashes = 0;
    for (char c : arg) {
        if (c == '\\') {
            ++slashes;
            continue;
        }
        // Backslashes are literal unless a quote follows: then each one needs escaping.
        out.append(c == '"' ? slashes * 2 + 1 : slashes, '\\');
        slashes = 0;
        out += c;
    }
    out.append(slashes * 2, '\\');  // before the closing quote
    out += '"';
    return out;
}

std::string win_command_line(const std::vector<std::string>& args) {
    std::string out;
    for (const std::string& a : args) {
        if (!out.empty()) out += ' ';
        out += win_quote_arg(a);
    }
    return out;
}

std::vector<std::string> restart_args(const std::string& config_dir, uint64_t wait_pid,
                                      const std::vector<std::string>& targets, bool no_session) {
    std::vector<std::string> a;  // push_back, not an init list: GCC 13 -Warray-bounds false positive
    a.push_back("--new-instance");
    if (no_session) a.push_back("--no-session");
    a.push_back("--wait-pid");
    a.push_back(std::to_string(wait_pid));
    if (!config_dir.empty()) {
        a.push_back("--config-dir");
        a.push_back(config_dir);
    }
    if (!targets.empty()) {
        a.push_back("--");
        for (const std::string& t : targets) a.push_back(t);
    }
    return a;
}

bool launch_elevated(const std::vector<std::string>& args, std::string* err, bool* cancelled) {
    if (cancelled) *cancelled = false;
    ElevatedLauncher f;
    {
        std::lock_guard<std::mutex> lk(g_launcher_mu);
        f = g_launcher;
    }
    return f ? f(args, err, cancelled) : os_launch(args, err, cancelled);
}

void set_elevated_launcher(ElevatedLauncher launcher) {
    std::lock_guard<std::mutex> lk(g_launcher_mu);
    g_launcher = std::move(launcher);
}

bool wait_process_exit(uint64_t pid, int timeout_ms) {
#ifdef _WIN32
    if (pid == 0 || pid > 0xFFFFFFFFull) return true;
    HANDLE h = OpenProcess(SYNCHRONIZE, FALSE, DWORD(pid));
    if (!h) return true;  // gone already (or not ours to watch)
    const DWORD r = WaitForSingleObject(h, DWORD(timeout_ms < 0 ? 0 : timeout_ms));
    CloseHandle(h);
    return r != WAIT_TIMEOUT;
#else
    if (pid == 0 || pid > uint64_t(INT32_MAX)) return true;
    const auto until = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    for (;;) {
        if (::kill(pid_t(pid), 0) != 0 && errno != EPERM) return true;
        if (std::chrono::steady_clock::now() >= until) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
#endif
}

}  // namespace hx
