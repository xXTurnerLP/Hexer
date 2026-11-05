#pragma once
// Process memory as a ByteBackend (core/file_source.h): offset = virtual address in the target
// process. Windows: OpenProcess + VirtualQueryEx region map + ReadProcessMemory / WriteProcessMemory.
// Linux: /proc/PID/maps + pread / pwrite on /proc/PID/mem (needs ptrace access: the same user with
// kernel.yama.ptrace_scope allowing it, or root).
//
// size() is process_address_limit(pid) (core/devices.h). Addresses outside a readable region
// (unmapped, reserved, no-access, guard pages) are holes: read() stops before them and
// next_readable() skips to the next readable region; they are never I/O errors. The region map
// is cached: refresh() re-reads it synchronously, and a lookup that falls outside every region
// asks a worker thread to re-read it, at most once per second (regions come and go while the
// process runs; listing a large process takes tens of ms, too long for the UI thread).
// Writes go straight into the target's memory without changing page protections: on Windows a
// write to a read-only page fails cleanly (write() returns false); Linux /proc/PID/mem writes
// force through read-only private mappings, as a debugger does. Unmapped pages always fail.
#include <cstdint>
#include <memory>
#include <string>

#include "core/file_source.h"

namespace hx {

// Opens the address space of `pid`; `write` also requests write access. Null + *err (with a hint
// about administrator / ptrace rights when access is denied) on failure.
std::unique_ptr<ByteBackend> open_process_backend(uint32_t pid, bool write, std::string* err = nullptr);

// "process://1234" -> 1234 (true); anything else false. The URL form is what Document::path()
// holds for a process document (and what Document::open_file accepts).
bool parse_process_url(const std::string& path, uint32_t* pid);
std::string process_url(uint32_t pid);

}  // namespace hx
