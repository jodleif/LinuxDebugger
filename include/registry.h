#pragma once
#include <array>
#include <cstdint>
#include <string>
#include <string_view>
namespace dbg {
enum class Reg {
    rax = 10,
    rbx = 5,
    rcx = 11,
    rdx = 12,
    rdi = 14,
    rsi = 13,
    rbp = 4,
    rsp = 19,
    r8 = 9,
    r9 = 8,
    r10 = 7,
    r11 = 6,
    r12 = 3,
    r13 = 2,
    r14 = 1,
    r15 = 0,
    rip = 16,
    eflags = 18,
    cs = 17,
    orig_rax = 15,
    fs_base = 21,
    gs_base = 22,
    fs = 25,
    gs = 26,
    ss = 20,
    ds = 23,
    es = 24
};

constexpr std::size_t n_registers{ 27 };

struct RegDescriptor {
    const Reg r;
    const std::int32_t dwarf_r;
    const std::string_view name;
};

using namespace std::string_view_literals;
// clang-format off
constexpr std::array<RegDescriptor, n_registers> g_register_descriptors
{ { { Reg::r15, 15, "r15"sv },
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
    { Reg::eflags, 49, "eflags"sv },
    { Reg::rsp, 7, "rsp"sv },
    { Reg::ss, 52, "ss"sv },
    { Reg::fs_base, 58, "fs_base"sv },
    { Reg::gs_base, 59, "gs_base"sv },
    { Reg::ds, 53, "ds"sv },
    { Reg::es, 50, "es"sv },
    { Reg::fs, 54, "fs"sv },
    { Reg::gs, 55, "gs"sv } } };
// clang-format on
std::uint64_t get_register_value(pid_t pid, Reg r);
void set_register_value(pid_t, Reg r, std::uint64_t value);
std::uint64_t get_register_value_from_dwarf_register(pid_t pid, unsigned regnum);
std::string_view get_register_name(Reg r);
Reg get_register_from_name(const std::string& name);
}
