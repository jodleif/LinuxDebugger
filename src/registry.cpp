#include "registry.h"
#include <algorithm>
#include <sys/ptrace.h>
#include <sys/user.h>

namespace {
std::size_t find_register_offset(dbg::Reg r)
{
    auto it = std::find_if(std::begin(dbg::g_register_descriptors), std::end(dbg::g_register_descriptors),
        [r](auto&& rd) { return rd.r == r; });
    return std::distance(std::begin(dbg::g_register_descriptors), it);
}
}

std::uint64_t dbg::get_register_value(const pid_t pid, const dbg::Reg r)
{
    user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, nullptr, &regs);

    // TODO: improve this
    auto offset = find_register_offset(r);
    return *(reinterpret_cast<std::uint64_t*>(&regs) + offset);
}

void dbg::set_register_value(const pid_t pid, const dbg::Reg r, const std::uint64_t value)
{
    user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, nullptr, &regs);

    auto offset = find_register_offset(r);
    *(reinterpret_cast<std::uint64_t*>(&regs) + offset) = value;
    ptrace(PTRACE_SETREGS, pid, nullptr, &regs);
}
