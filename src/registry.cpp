#include "registry.h"
#include "config.h"
#include <algorithm>
#include <cassert>
#include <cerrno>
#include <functional>
#include <iostream>
#include <libexplain/ptrace.h>
#include <sys/ptrace.h>
#include <sys/user.h>

namespace {
// TODO: improve find_register_offset, potentially UB

class RegsAccessor {
    user_regs_struct* regs;

public:
    RegsAccessor() = delete;
    explicit RegsAccessor(user_regs_struct* _regs)
        : regs(_regs)
    {
    }

    unsigned long long& operator[](dbg::Reg r)
    {
        switch (r) {
        case dbg::Reg::rax:
            return std::ref(regs->rax);
        case dbg::Reg::rbx:
            return std::ref(regs->rbx);
        case dbg::Reg::rcx:
            return std::ref(regs->rcx);
        case dbg::Reg::rdx:
            return std::ref(regs->rdx);
        case dbg::Reg::rdi:
            return std::ref(regs->rdi);
        case dbg::Reg::rsi:
            return std::ref(regs->rsi);
        case dbg::Reg::rbp:
            return std::ref(regs->rbp);
        case dbg::Reg::rsp:
            return std::ref(regs->rsp);
        case dbg::Reg::r8:
            return std::ref(regs->r8);
        case dbg::Reg::r9:
            return std::ref(regs->r9);
        case dbg::Reg::r10:
            return std::ref(regs->r10);
        case dbg::Reg::r11:
            return std::ref(regs->r11);
        case dbg::Reg::r12:
            return std::ref(regs->r12);
        case dbg::Reg::r13:
            return std::ref(regs->r13);
        case dbg::Reg::r14:
            return std::ref(regs->r14);
        case dbg::Reg::r15:
            return std::ref(regs->r15);
        case dbg::Reg::rip:
            return std::ref(regs->rip);
        case dbg::Reg::eflags:
            return std::ref(regs->eflags);
        case dbg::Reg::cs:
            return std::ref(regs->cs);
        case dbg::Reg::orig_rax:
            return std::ref(regs->orig_rax);
        case dbg::Reg::fs_base:
            return std::ref(regs->fs_base);
        case dbg::Reg::gs_base:
            return std::ref(regs->gs_base);
        case dbg::Reg::fs:
            return std::ref(regs->fs);
        case dbg::Reg::gs:
            return std::ref(regs->gs);
        case dbg::Reg::ss:
            return std::ref(regs->ss);
        case dbg::Reg::ds:
            return std::ref(regs->ds);
        case dbg::Reg::es:
            return std::ref(regs->es);
        }
        throw std::out_of_range{ "[RegAccessor] invalid Reg" };
    }
    // user_regs_struct* operator()() { return regs; }
};

} // end anonymous namespace

std::uint64_t dbg::get_register_value(const pid_t pid, const dbg::Reg r)
{
    user_regs_struct regs{};
    auto data = ptrace(PTRACE_GETREGS, pid, nullptr, &regs);
    if constexpr (dbg::debug) {
        if (data < 0) {
            int err = errno;
            std::cerr << explain_errno_ptrace(err, PTRACE_GETREGS, pid, nullptr, &regs) << std::endl;
        }
    }
    auto acc = RegsAccessor{ &regs };

    return acc[r];
}

void dbg::set_register_value(const pid_t pid, const dbg::Reg r, const std::uint64_t value)
{
    user_regs_struct regs{};
    auto data = ptrace(PTRACE_GETREGS, pid, nullptr, &regs);
    if constexpr (dbg::debug) {
        if (data < 0) {
            int err = errno;
            std::cerr << explain_errno_ptrace(err, PTRACE_GETREGS, pid, nullptr, &regs) << std::endl;
        }
    }

    auto acc = RegsAccessor{ &regs };
    acc[r] = value;
    data = ptrace(PTRACE_SETREGS, pid, nullptr, &regs);
    if constexpr (dbg::debug) {
        if (data < 0) {
            int err = errno;
            std::cerr << explain_errno_ptrace(err, PTRACE_SETREGS, pid, nullptr, &regs) << std::endl;
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

std::string_view dbg::get_register_name(const dbg::Reg r)
{
    const auto idx = static_cast<std::size_t>(r);
    assert(idx < n_registers);
    const auto& desc = g_register_descriptors[idx];
    return desc.name;
}

dbg::Reg dbg::get_register_from_name(const std::string& name)
{
    auto it = std::find_if(std::begin(g_register_descriptors), std::end(g_register_descriptors),
        [&name](auto&& desc) { return desc.name == name; });
    return it->r;
}
