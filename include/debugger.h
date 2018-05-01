#pragma once
#include "breakpoint.h"
#include <bits/types/siginfo_t.h>
#include <dwarf/dwarf++.hh>
#include <elf/elf++.hh>
#include <fcntl.h>
#include <string>
#include <unistd.h>
#include <unordered_map>

namespace dbg {
//forward decl
class Symbol;

class Debugger {
    std::string prog_name;
    pid_t pid;
    std::unordered_map<std::intptr_t, Breakpoint> breakpoints;
    elf::elf elf;
    dwarf::dwarf dwarf;

    void handle_command(std::string const& line);
    void continue_execution();
    siginfo_t get_signal_info();
    void wait_for_signal();
    void handle_sigtrap(siginfo_t info);
    void single_step_instruction();

public:
    Debugger(std::string _prog_name, pid_t _pid)
        : prog_name{ std::move(_prog_name) }
        , pid{ _pid }
    {
        auto fd = open(prog_name.c_str(), O_RDONLY);

        elf = elf::elf{ elf::create_mmap_loader(fd) };
        dwarf = dwarf::dwarf{ dwarf::elf::create_loader(elf) };
    }
    void run();
    void set_breakpoint_at_address(std::intptr_t address);
    void remove_breakpoint(std::intptr_t address);
    void set_breakpoint_at_function(const std::string& name);
    void set_breakpoint_at_source_line(const std::string& file, const std::uint32_t line);

    std::vector<Symbol> lookup_symbol(const std::string& name);

    void dump_registers();
    std::uint64_t read_memory(std::uint64_t address);
    void write_memory(std::uint64_t address, std::uint64_t value);
    std::uint64_t get_program_counter();
    std::intptr_t get_program_counteri();
    void set_program_counter(std::uint64_t pc);
    void step_over_breakpoint();
    dwarf::die get_function_from_program_counter(std::uint64_t program_counter);
    dwarf::line_table::iterator get_line_entry_from_program_counter(std::uint64_t program_counter);
    void print_source(const std::string& file_name, std::uint32_t line, std::uint32_t n_lines_context = 2);

    void single_step_instruction_with_breakpoint_check();
    void step_out();
    void step_in();
    void step_over();
};
} // end namespace dbg
