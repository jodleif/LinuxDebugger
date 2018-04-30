#include "debugger.h"
#include "config.h"
#include "linenoise.h"
#include "registry.h"
#include <cassert>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <libexplain/ptrace.h>
#include <sstream>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <vector>

namespace {
std::vector<std::string> split(std::string const& s, char delimiter)
{
    std::vector<std::string> out{};
    std::stringstream ss{ s };
    std::string item;
    while (std::getline(ss, item, delimiter)) {
        out.push_back(item);
    }
    return out;
}
bool is_prefix(const std::string& s, const std::string& of)
{
    if (s.size() > of.size()) {
        return false;
    }
    return std::equal(s.begin(), s.end(), of.begin());
}
}

void dbg::Debugger::handle_command(const std::string& line)
{
    auto args = split(line, ' ');
    auto command = args[0];
    if (is_prefix(command, "cont")) {
        continue_execution();
    } else if (is_prefix(command, "break")) {
        std::string addr{ args[1], 2 };
        set_breakpoint_at_address(std::stol(addr, nullptr, 16));
    } else if (is_prefix(command, "register")) {
        if (is_prefix(args[1], "dump")) {
            dump_registers();
        } else if (is_prefix(args[1], "read")) {
            assert(args.size() > 2);
            std::cout << get_register_value(pid, get_register_from_name(args[2])) << std::endl;
        } else if (is_prefix(args[1], "write")) {
            assert(args.size() > 3);
            std::string val{ args[3], 2 };
            set_register_value(pid, get_register_from_name(args[2]), std::stoul(val, nullptr, 16));
        }
    } else if (is_prefix(command, "memory")) {
        assert(args.size() > 2);
        std::string addr{ args[2], 2 };
        auto addr_{ std::stoul(addr, nullptr, 16) };
        if (is_prefix(args[1], "read")) {
            std::cout << std::hex << read_memory(addr_) << std::endl;
        } else if (is_prefix(args[1], "write")) {
            assert(args.size() > 3);
            std::string val{ args[3], 2 };
            write_memory(addr_, std::stoul(val, nullptr, 16));
        }
    } else {
        std::cerr << "Unknown command\n";
    }
}

void dbg::Debugger::continue_execution()
{
    step_over_breakpoint();
    ptrace(PTRACE_CONT, pid, nullptr, nullptr);
    wait_for_signal();
}

siginfo_t dbg::Debugger::get_signal_info()
{
    siginfo_t info;
    auto res = ptrace(PTRACE_GETSIGINFO, pid, nullptr, &info);
    if (res < 0) {
        if constexpr (debug) {
            int err = errno;
            std::fprintf(stderr, "%s\n", explain_errno_ptrace(err, PTRACE_GETSIGINFO, pid, nullptr, nullptr));
        }
    }
    return info;
}

void dbg::Debugger::run()
{
    int wait_status;
    int options = 0;
    waitpid(pid, &wait_status, options);

    char* line = nullptr;
    while ((line = linenoise("minidbg> ")) != nullptr) {
        handle_command(line);
        linenoiseHistoryAdd(line);
        linenoiseFree(line);
    }
}

void dbg::Debugger::set_breakpoint_at_address(std::intptr_t address)
{
    std::cout << "Set breakpoint at address 0x" << std::hex << address << std::endl;
    dbg::Breakpoint bp(pid, address);
    bp.enable();
    breakpoints[static_cast<std::uint64_t>(address)] = bp;
}

void dbg::Debugger::dump_registers()
{
    for (const auto& rd : g_register_descriptors) {
        std::cout << rd.name << " 0x"
                  << std::setfill('0') << std::setw(16) << std::hex
                  << get_register_value(pid, rd.r) << std::endl;
    }
}

void dbg::Debugger::write_memory(uint64_t address, uint64_t value)
{
    auto res = ptrace(PTRACE_POKEDATA, pid, address, value);
    if (res < 0) {
        if constexpr (debug) {
            int err = errno;
            std::fprintf(stderr, "%s\n", explain_errno_ptrace(err, PTRACE_PEEKDATA, pid, reinterpret_cast<void*>(address), nullptr));
        }
    }
}

std::uint64_t dbg::Debugger::read_memory(uint64_t address)
{
    auto data = ptrace(PTRACE_PEEKDATA, pid, address, nullptr);
    if (data < 0) {
        if constexpr (debug) {
            int err = errno;
            std::fprintf(stderr, "%s\n", explain_errno_ptrace(err, PTRACE_PEEKDATA, pid, reinterpret_cast<void*>(address), nullptr));
        }
        return 0;
    }
    return static_cast<std::uint64_t>(data);
}

std::uint64_t dbg::Debugger::get_program_counter()
{
    return get_register_value(pid, Reg::rip);
}

void dbg::Debugger::set_program_counter(std::uint64_t pc)
{
    set_register_value(pid, Reg::rip, pc);
}

void dbg::Debugger::step_over_breakpoint()
{

    auto pc = get_program_counter();
    if (breakpoints.count(pc) > 0) {
        auto& bp = breakpoints[pc];

        if (bp.is_enabled()) {
            bp.disable();
            ptrace(PTRACE_SINGLESTEP, pid, nullptr, nullptr);
            wait_for_signal();
            bp.enable();
        }
    }
}

void dbg::Debugger::wait_for_signal()
{
    int wait_status;
    auto options = 0;
    waitpid(pid, &wait_status, options);

    auto siginfo = get_signal_info();

    switch (siginfo.si_signo) {
    case SIGTRAP:
        handle_sigtrap(siginfo);
        break;
    case SIGSEGV:
        std::cerr << "Segfault. Reason: " << siginfo.si_code << std::endl;
        break;
    default:
        std::cout << "Got signal " << strsignal(siginfo.si_signo) << std::endl;
    }
}

void dbg::Debugger::handle_sigtrap(siginfo_t info)
{
    switch (info.si_code) {
    case SI_KERNEL:
    case TRAP_BRKPT: {
        set_program_counter(get_program_counter() - 1);
        std::cout << "Hit breakpoint at address 0x" << std::hex << get_program_counter() << std::endl;
        auto line_entry = get_line_entry_from_program_counter(get_program_counter());
        print_source(line_entry->file->path, line_entry->line);
        return;
    }
    case TRAP_TRACE:
        return;
    default:
        std::cout << "Unknown SIGTRAP code " << info.si_code << std::endl;
    }
}

dwarf::die dbg::Debugger::get_function_from_program_counter(std::uint64_t program_counter)
{
    for (auto& cu : dwarf.compilation_units()) {
        if (dwarf::die_pc_range(cu.root()).contains(program_counter)) {
            for (const auto& die : cu.root()) {
                if (die.tag == dwarf::DW_TAG::subprogram) {
                    if (dwarf::die_pc_range(die).contains(program_counter)) {
                        return die;
                    }
                }
            }
        }
    }
    throw std::out_of_range{ "Cannot find function" };
}

dwarf::line_table::iterator dbg::Debugger::get_line_entry_from_program_counter(const std::uint64_t program_counter)
{
    for (auto& cu : dwarf.compilation_units()) {
        if (dwarf::die_pc_range(cu.root()).contains(program_counter)) {
            auto& lt = cu.get_line_table();
            auto it = lt.find_address(program_counter);
            if (it != lt.end()) {
                return it;
            }
            break;
        }
    }
    throw std::out_of_range{ "Cannot find line entry" };
}

void dbg::Debugger::print_source(const std::string& file_name, uint32_t line, uint32_t n_lines_context)
{
    std::ifstream file{ file_name };

    auto start_line = line <= n_lines_context ? 1 : line - n_lines_context;
    auto end_line = line + n_lines_context + (line < n_lines_context ? n_lines_context - line : 0) + 1;

    char c{};
    auto current_line{ 1u };

    // skip lines to start_line
    // TODO REWRITE
    while (current_line != start_line && file.get(c)) {
        if (c == '\n') {
            ++current_line;
        }
    }

    std::cout << (current_line == line ? "> " : "  ");

    // TODO: rewrite
    while (current_line <= end_line && file.get(c)) {
        std::cout << c;
        if (c == '\n') {
            ++current_line;

            std::cout << (current_line == line ? "> " : "  ");
        }
    }
    std::cout << std::endl;
}
