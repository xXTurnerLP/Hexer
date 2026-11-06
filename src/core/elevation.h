#pragma once
// "Restart as Administrator" (Windows): elevation check, the command line of the elevated instance
// and its launch. No UI. The handover protocol (see App's restart_as_admin):
//   1. the running instance writes its hot-exit session, then launches itself elevated with
//      restart_args(): --new-instance (never forward the files to this or another running Hexer),
//      --wait-pid <its pid>, --config-dir <its config dir> and the targets the session cannot hold
//      (process://<pid>, the disk being opened) after "--";
//   2. only when the launch succeeded (UAC accepted) it quits normally (hot exit, settings,
//      layout); a cancelled UAC prompt leaves it running untouched;
//   3. the elevated instance waits (wait_process_exit) until the old one has exited - so it has
//      released the session lock and written its last state - and then restores that session as
//      usual: every unsaved edit arrives exactly once.
// Linux: no elevation (can_restart_elevated() is false); the "run as root" hints stay.
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace hx {

// Running with administrator rights: Windows: the process token is elevated (TokenElevation);
// POSIX: effective uid 0.
bool os_elevated();
// "Restart as Administrator" is offered: Windows and not elevated yet.
bool can_restart_elevated();

// One argument quoted for a Windows command line so that CommandLineToArgvW (and the MSVC CRT)
// give it back unchanged: quotes only when needed (empty, blanks, '"'), backslashes doubled only
// before a quote. UTF-8 in, UTF-8 out (non-ASCII bytes pass through). Pure; on every platform.
std::string win_quote_arg(const std::string& arg);
// The arguments quoted and joined with single spaces (no program name).
std::string win_command_line(const std::vector<std::string>& args);

// The elevated instance's arguments (step 1 above): "--new-instance", "--no-session" (only with
// `no_session`: this instance runs without a session, so must the new one), "--wait-pid", <pid>,
// "--config-dir", <config_dir> (omitted when empty), then "--" and the targets (omitted when none).
std::vector<std::string> restart_args(const std::string& config_dir, uint64_t wait_pid,
                                      const std::vector<std::string>& targets, bool no_session = false);

// Starts this executable elevated with `args` (Windows: ShellExecuteExW, verb "runas": the UAC
// prompt; blocks while it is shown). False + *err on failure; *cancelled = true when the user
// declined the prompt. Elsewhere always false ("not supported"). The environment variable
// HEXER_TEST_RESTART_VERB (e.g. "open") replaces the verb: automated runs test the handover
// without a UAC prompt.
bool launch_elevated(const std::vector<std::string>& args, std::string* err = nullptr, bool* cancelled = nullptr);
// Tests: replaces what launch_elevated does (an empty function restores the OS launch).
using ElevatedLauncher = std::function<bool(const std::vector<std::string>& args, std::string* err, bool* cancelled)>;
void set_elevated_launcher(ElevatedLauncher launcher);

// Waits up to timeout_ms for process `pid` to exit. True once it is gone (or cannot be watched:
// never blocks a start on a pid we may not query); false on timeout.
bool wait_process_exit(uint64_t pid, int timeout_ms);

}  // namespace hx
