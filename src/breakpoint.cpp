#include "breakpoint.h"
#include "config.h"
#include <cerrno>
#include <cstdio>
#include <libexplain/ptrace.h>
#include <sys/ptrace.h>

void dbg::Breakpoint::enable()
{
    auto data = ptrace(PTRACE_PEEKDATA, pid, addr, nullptr);
    if constexpr (dbg::debug) {
        if (data < 0) {
            int err = errno;
            std::fprintf(stderr, "%s\n", explain_errno_ptrace(err, PTRACE_PEEKDATA, pid, reinterpret_cast<void*>(addr), nullptr));
        }
    }
    saved_data = static_cast<std::uint8_t>(data & 0xFF);
    std::uint64_t int3 = 0xCC;
    std::uint64_t data_with_int3 = ((std::uint64_t(data) & ~0xFFul) | int3);
    ptrace(PTRACE_POKETEXT, pid, addr, data_with_int3);

    enabled = true;
}

void dbg::Breakpoint::disable()
{
    auto data = ptrace(PTRACE_PEEKDATA, pid, addr, nullptr);
    auto restored_data = ((data & ~0xFF) | saved_data);
    ptrace(PTRACE_POKEDATA, pid, addr, restored_data);

    enabled = false;
}
