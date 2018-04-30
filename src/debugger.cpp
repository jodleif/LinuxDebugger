#include "debugger.h"
#include "config.h"
#include "linenoise.h"
#include "registry.h"
#include <cassert>
#include <iomanip>
#include <iostream>
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
    } else {
        std::cerr << "Unknown command\n";
    }
}

void dbg::Debugger::continue_execution()
{
    ptrace(PTRACE_CONT, pid, nullptr, nullptr);

    int wait_status;
    int options = 0;
    waitpid(pid, &wait_status, options);
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

void dbg::Debugger::dump_registers()
{
    for (const auto& rd : g_register_descriptors) {
        std::cout << rd.name << " 0x"
                  << std::setfill('0') << std::setw(16) << std::hex
                  << get_register_value(pid, rd.r) << std::endl;
    }
}
