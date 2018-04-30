#pragma once
#include <array>
#include <cstdint>
#include <string>
#include <string_view>
namespace dbg {
enum class Reg {
    rax,
    rbx,
    rcx,
    rdx,
    rdi,
    rsi,
    rbp,
    rsp,
    r8,
    r9,
    r10,
    r11,
    r12,
    r13,
    r14,
    r15,
    rip,
    rflags,
    cs,
    orig_rax,
    fs_base,
    gs_base,
    fs,
    gs,
    ss,
    ds,
    es
};

constexpr std::size_t n_registers{ 27 };

struct RegDescriptor {
    const Reg r;
    const std::int32_t dwarf_r;
    const std::string_view name;
};
using namespace std::string_view_literals;
constexpr std::array<RegDescriptor, n_registers> g_register_descriptors{ { { Reg::r15, 15, "r15"sv },
    { Reg::r14, 14, "r14"sv },
    { Reg::r13, 13, "r13"sv },
    { Reg::r12, 12, "r12"sv },
    { Reg::rbp, 6, "rbp"sv },
    { Reg::rbx, 3, "rbx"sv },
    { Reg::r11, 11, "r11"sv },
    { Reg::r10, 10, "r10"sv },
    { Reg::r9, 9, "r9"sv },
    { Reg::r8, 8, "r8"sv },
    { Reg::rax, 0, "rax"sv },
    { Reg::rcx, 2, "rcx"sv },
    { Reg::rdx, 1, "rdx"sv },
    { Reg::rsi, 4, "rsi"sv },
    { Reg::rdi, 5, "rdi"sv },
    { Reg::orig_rax, -1, "orig_rax"sv },
    { Reg::rip, -1, "rip"sv },
    { Reg::cs, 51, "cs"sv },
    { Reg::rflags, 49, "eflags"sv },
    { Reg::rsp, 7, "rsp"sv },
    { Reg::ss, 52, "ss"sv },
    { Reg::fs_base, 58, "fs_base"sv },
    { Reg::gs_base, 59, "gs_base"sv },
    { Reg::ds, 53, "ds"sv },
    { Reg::es, 50, "es"sv },
    { Reg::fs, 54, "fs"sv },
    { Reg::gs, 55, "gs"sv } } };

std::uint64_t get_register_value(pid_t pid, Reg r);
void set_register_value(pid_t, Reg r, std::uint64_t value);
std::uint64_t get_register_value_from_dwarf_register(pid_t pid, unsigned regnum);
std::string_view get_register_name(Reg r);
Reg get_register_from_name(const std::string& name);
}
