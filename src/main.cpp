#include "debugger.h"
#include "registry.h"
#include <iostream>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <utility>

namespace {
}

int main(int argc, char const* argv[])
{
    std::string program_name{};
    if (argc >= 2) {
        program_name = argv[1];
    }

    auto* prog = program_name.c_str();
    auto pid = fork();
    if (pid == 0) {
        // child process \ execute debuggeee
        personality(ADDR_NO_RANDOMIZE);
        std::cout << "Child process: [" << prog << ']' << std::endl;
        auto res = ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
        if (res < 0) {
            std::cerr << "Error in ptrace\n";
        }
        execl(prog, prog, nullptr);
    } else if (pid >= 1) {
        dbg::Debugger dbg{ prog, pid };
        dbg.run();
    }

    return 0;
}
