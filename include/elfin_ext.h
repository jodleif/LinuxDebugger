#pragma once
#include <dwarf/dwarf++.hh>
#include <sys/ptrace.h>

class ptrace_expr_context : public dwarf::expr_context {
    pid_t pid;

public:
    ptrace_expr_context(pid_t pid_)
        : pid{ pid_ }
    {
    }
    dwarf::taddr reg(unsigned regnum) override;
    dwarf::taddr pc();
    dwarf::taddr deref_size(dwarf::taddr address, unsigned size) override;
};
