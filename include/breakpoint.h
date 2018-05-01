#pragma once
#include <cstdint>
#include <unistd.h>
namespace dbg {
class Breakpoint {
    pid_t pid;
    std::intptr_t addr;
    bool enabled;
    std::uint8_t saved_data;

public:
    Breakpoint() = default;
    Breakpoint(pid_t _pid, std::intptr_t _addr)
        : pid{ _pid }
        , addr{ _addr }
        , enabled{ false }
        , saved_data{ 0 }
    {
    }

    void enable();
    void disable();

    auto is_enabled() const -> bool { return enabled; }
    auto get_address() const -> std::intptr_t { return addr; }
};
} // end namespace dbg
