#include "debugger.h"
#include "config.h"
#include "linenoise.h"
#include "registry.h"
#include "symbol_type.h"
#include <algorithm>
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

bool is_suffix(const std::string& s, const std::string& of)
{
    if (s.size() > of.size()) {
        return false;
    }
    return std::equal(s.rbegin(), s.rend(), of.rbegin());
}
} // end anonymous namespace

void dbg::Debugger::handle_command(const std::string& line)
{
    auto args = split(line, ' ');
    auto command = args[0];
    if (is_prefix(command, "cont")) {
        continue_execution();
    } else if (is_prefix(command, "break")) {
        if (is_prefix("0x", args[1])) {
            std::string addr{ args[1], 2 };
            set_breakpoint_at_address(std::stol(addr, nullptr, 16));
        } else if (args[1].find(':') != std::string::npos) {
            auto file_and_line = split(args[1], ':');
            set_breakpoint_at_source_line(file_and_line[0], static_cast<std::uint32_t>(std::stoi(file_and_line[1])));
        } else {
            set_breakpoint_at_function(args[1]);
        }
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
    } else if (is_prefix(command, "symbol")) {
        auto syms = lookup_symbol(args[1]);
        for (const auto& s : syms) {
            std::cout << s.name << ' ' << to_string(s.type) << " 0x" << std::hex << s.addr << std::endl;
        }
    } else if (is_prefix(command, "stepi")) {
        single_step_instruction_with_breakpoint_check();
        auto line_entry = get_line_entry_from_program_counter(get_program_counter());
        print_source(line_entry->file->path, line_entry->line, 2);
    } else if (is_prefix(command, "step")) {
        step_in();
    } else if (is_prefix(command, "next")) {
        step_over();
    } else if (is_prefix(command, "finish")) {
        step_out();
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
    breakpoints[address] = bp;
}

void dbg::Debugger::remove_breakpoint(intptr_t address)
{
    assert(breakpoints.count(address) > 0);
    if (breakpoints.at(address).is_enabled()) {
        breakpoints.at(address).disable();
    }
    breakpoints.erase(address);
}

void dbg::Debugger::set_breakpoint_at_function(const std::string& name)
{
    for (const auto& cu : dwarf.compilation_units()) {
        for (const auto& die : cu.root()) {
            if (die.has(dwarf::DW_AT::name) && at_name(die) == name) {
                auto low_pc = at_low_pc(die);
                auto entry = get_line_entry_from_program_counter(low_pc);
                ++entry; // skip prologue
                set_breakpoint_at_address(static_cast<std::intptr_t>(entry->address));
            }
        }
    }
}

void dbg::Debugger::set_breakpoint_at_source_line(const std::string& file, const uint32_t line)
{
    for (const auto& cu : dwarf.compilation_units()) {
        if (is_suffix(file, at_name(cu.root()))) {
            const auto& lt = cu.get_line_table();

            for (const auto& entry : lt) {
                if (entry.is_stmt && entry.line == line) {
                    set_breakpoint_at_address(static_cast<std::intptr_t>(entry.address));
                    return;
                }
            }
        }
    }
}

std::vector<dbg::Symbol> dbg::Debugger::lookup_symbol(const std::string& name)
{
    std::vector<Symbol> syms;

    for (const auto& sec : elf.sections()) {
        if (auto type = sec.get_hdr().type; type != elf::sht::symtab && type != elf::sht::dynsym) {
            continue;
        }

        for (const auto& sym : sec.as_symtab()) {
            if (sym.get_name() == name) {
                auto& d = sym.get_data();
                syms.push_back(Symbol{ to_symbol_type(d.type()), sym.get_name(), d.value });
            }
        }
    }
    return syms;
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

std::intptr_t dbg::Debugger::get_program_counteri()
{
    return static_cast<std::intptr_t>(get_program_counter());
}

void dbg::Debugger::set_program_counter(std::uint64_t pc)
{
    set_register_value(pid, Reg::rip, pc);
}

void dbg::Debugger::step_over_breakpoint()
{

    auto pc = get_program_counteri();
    if (breakpoints.count(pc) > 0) {
        auto& bp = breakpoints[pc];

        if (bp.is_enabled()) {
            bp.disable();
            single_step_instruction();
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

void dbg::Debugger::single_step_instruction()
{
    ptrace(PTRACE_SINGLESTEP, pid, nullptr, nullptr);
    wait_for_signal();
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

void dbg::Debugger::single_step_instruction_with_breakpoint_check()
{
    // do we need to enable and disable breakpoint?
    if (breakpoints.count(get_program_counteri()) > 0) {
        step_over_breakpoint();
    } else {
        single_step_instruction();
    }
}

void dbg::Debugger::step_out()
{
    auto frame_pointer = get_register_value(pid, Reg::rbp);
    auto return_address = static_cast<std::intptr_t>(read_memory(frame_pointer + 8));

    bool should_remove_breakpoint{ false };
    if (breakpoints.count(return_address) == 0) {
        set_breakpoint_at_address(return_address);
        should_remove_breakpoint = true;
    }

    continue_execution();

    if (should_remove_breakpoint) {
        remove_breakpoint(return_address);
    }
}

void dbg::Debugger::step_in()
{
    auto line = get_line_entry_from_program_counter(get_program_counter())->line;

    while (get_line_entry_from_program_counter(get_program_counter())->line == line) {
        single_step_instruction_with_breakpoint_check();
    }

    auto line_entry = get_line_entry_from_program_counter(get_program_counter());
    print_source(line_entry->file->path, line_entry->line);
}

void dbg::Debugger::step_over()
{
    dwarf::die func;
    std::uint64_t func_entry, func_end{};
    try {
        func = get_function_from_program_counter(get_program_counter());
        func_entry = at_low_pc(func);
        func_end = at_high_pc(func);
    } catch (std::out_of_range& exp) {
        std::cerr << "Program counter: " << std::hex << get_program_counter() << std::endl;
        std::cerr << "Out of range " << exp.what() << std::endl;
        return;
    }
    auto line = get_line_entry_from_program_counter(func_entry);
    auto start_line = get_line_entry_from_program_counter(get_program_counter());

    std::vector<std::intptr_t> to_delete{};

    while (line->address < func_end) {
        if (auto laddr = static_cast<std::intptr_t>(line->address); line->address != start_line->address && (breakpoints.count(laddr) == 0)) {
            set_breakpoint_at_address(laddr);
            to_delete.push_back(laddr);
        }
        ++line;
    }

    auto frame_pointer = get_register_value(pid, Reg::rbp);
    auto return_address = static_cast<std::intptr_t>(read_memory(frame_pointer + 8));
    if (breakpoints.count(return_address) == 0) {
        set_breakpoint_at_address(return_address);
        to_delete.push_back(return_address);
    }

    continue_execution();

    for (auto addr : to_delete) {
        remove_breakpoint(addr);
    }
}
