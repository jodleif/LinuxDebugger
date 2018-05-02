#include "elfin_ext.h"
#include "registry.h"
#include <sys/user.h>

dwarf::taddr ptrace_expr_context::reg(unsigned regnum)
{
    return dbg::get_register_value_from_dwarf_register(pid, regnum);
}

dwarf::taddr ptrace_expr_context::pc()
{
    user_regs_struct regs{};
    ptrace(PTRACE_GETREGS, pid, nullptr, &regs);
    return regs.rip;
}

dwarf::taddr ptrace_expr_context::deref_size(dwarf::taddr address, unsigned size)
{
    //TODO take size into account ?
    return ptrace(PTRACE_PEEKDATA, pid, address, nullptr);
}
