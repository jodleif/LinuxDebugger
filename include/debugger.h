#pragma once
#include "breakpoint.h"
#include <string>
#include <unistd.h>
#include <unordered_map>

namespace dbg {
class Debugger {
    std::string prog_name;
    pid_t pid;
    std::unordered_map<std::intptr_t, Breakpoint> breakpoints;

    void handle_command(std::string const& line);
    void continue_execution();

public:
    Debugger(std::string _prog_name, pid_t _pid)
        : prog_name{ std::move(_prog_name) }
        , pid{ _pid }
    {
    }
    void run();
    void set_breakpoint_at_address(std::intptr_t address);
    void dump_registers();
    std::uint64_t read_memory(std::uint64_t address);
    void write_memory(std::uint64_t address, std::uint64_t value);
    std::uint64_t get_program_counter();
    void set_program_counter(std::uint64_t pc);
    void step_over_breakpoint();
    void wait_for_signal();
};
}
