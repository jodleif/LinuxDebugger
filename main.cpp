#include "debugger.h"
#include <iostream>
#include <sys/ptrace.h>
#include <unistd.h>
#include <utility>

namespace {
}

int main(int argc, char const* argv[])
{
    std::string program_name{ "to-debug" };
    std::cout << "Size of intptr_t: " << sizeof(std::intptr_t) << '\n';
    if (argc >= 2) {
        program_name = argv[1];
    }
    auto* prog = program_name.c_str();
    auto pid = fork();

    if (pid == 0) {
        // child process \ execute debuggeee
        std::cout << "Child procesS!" << prog << std::endl;
        auto res = ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
        if (res < 0) {
            std::cerr << "Error in ptrace\n";
        }
        execl(prog, prog, nullptr);
    } else if (pid >= 1) {
        std::cout << "Debugger !!! " << std::endl;
        dbg::Debugger dbg{ prog, pid };
        dbg.run();
    }

    return 0;
}
