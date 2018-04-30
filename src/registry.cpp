#include "registry.h"
#include <algorithm>
#include <sys/ptrace.h>
#include <sys/user.h>

std::uint64_t dbg::get_register_value(const pid_t pid, const dbg::Reg r)
{
    user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, nullptr, &regs);

    // TODO: improve this
    auto it = std::find_if(std::begin(dbg::g_register_descriptors), std::end(dbg::g_register_descriptors),
        [r](auto&& rd) { return rd.r == r; });
    return *(reinterpret_cast<std::uint64_t*>(&regs) + (it - std::begin(dbg::g_register_descriptors)));
}
