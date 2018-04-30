#include "registry.h"
#include "config.h"
#include <algorithm>
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <libexplain/ptrace.h>
#include <sys/ptrace.h>
#include <sys/user.h>

namespace {
// TODO: improve find_register_offset, potentially UB
std::size_t find_register_offset(dbg::Reg r)
{
    auto it = std::find_if(std::begin(dbg::g_register_descriptors), std::end(dbg::g_register_descriptors),
        [r](auto&& rd) { return rd.r == r; });
    auto res = std::distance(std::begin(dbg::g_register_descriptors), it);
    assert(res >= 0);
    return static_cast<std::size_t>(res);
}
}

std::uint64_t dbg::get_register_value(const pid_t pid, const dbg::Reg r)
{
    user_regs_struct regs;
    auto data = ptrace(PTRACE_GETREGS, pid, nullptr, &regs);
    if constexpr (dbg::debug) {
        if (data < 0) {
            int err = errno;
            std::fprintf(stderr, "%s\n", explain_errno_ptrace(err, PTRACE_GETREGS, pid, nullptr, &regs));
        }
    }

    auto offset = find_register_offset(r);
    return *(reinterpret_cast<std::uint64_t*>(&regs) + offset);
}

void dbg::set_register_value(const pid_t pid, const dbg::Reg r, const std::uint64_t value)
{
    user_regs_struct regs;
    auto data = ptrace(PTRACE_GETREGS, pid, nullptr, &regs);
    if constexpr (dbg::debug) {
        if (data < 0) {
            int err = errno;
            std::fprintf(stderr, "%s\n", explain_errno_ptrace(err, PTRACE_GETREGS, pid, nullptr, &regs));
        }
    }

    auto offset = find_register_offset(r);
    *(reinterpret_cast<std::uint64_t*>(&regs) + offset) = value;
    data = ptrace(PTRACE_SETREGS, pid, nullptr, &regs);
    if constexpr (dbg::debug) {
        if (data < 0) {
            int err = errno;
            std::fprintf(stderr, "%s\n", explain_errno_ptrace(err, PTRACE_SETREGS, pid, nullptr, &regs));
        }
    }
}

std::uint64_t dbg::get_register_value_from_dwarf_register(pid_t pid, unsigned regnum)
{
    auto it = std::find_if(std::begin(g_register_descriptors), std::end(g_register_descriptors),
        [regnum](auto&& rd) { return rd.dwarf_r == static_cast<std::int32_t>(regnum); });

    if (it == std::end(g_register_descriptors)) {
        throw std::out_of_range{ "Unknown dwarf register" };
    }
    return get_register_value(pid, it->r);
}

std::string_view dbg::get_register_name(dbg::Reg r)
{
    auto it = std::find_if(std::begin(g_register_descriptors), std::end(g_register_descriptors),
        [r](auto&& desc) {
            return desc.r == r;
        });
    return it->name;
}

dbg::Reg dbg::get_register_from_name(const std::string& name)
{
    auto it = std::find_if(std::begin(g_register_descriptors), std::end(g_register_descriptors),
        [&name](auto&& desc) { return desc.name == name; });
    return it->r;
}
