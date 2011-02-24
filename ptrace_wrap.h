/*  This file is part of fossa
    Copyright (C) 2011  James A. Shackleford

    fossa is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _ptrace_wrap_h_
#define _ptrace_wrap_h_

#include "fossa.h"

void
pt_attach (pid_t pid);

void
pt_detach (pid_t pid);

void
pt_allow_trace (void);

void
pt_continue (pid_t pid);

void 
pt_peek (pid_t pid, Elf_Addr addr, void *vptr, unsigned int len);

void 
pt_poke (pid_t pid, Elf_Addr addr, void *vptr, unsigned int len);

char *
pt_get_str (pid_t pid, Elf_Addr addr);

void
pt_singlestep (pid_t pid);

void
pt_get_regs (pid_t pid, struct user_regs_struct* regs);

void
pt_set_regs (pid_t pid, struct user_regs_struct* regs);

long
pt_set_breakpoint (pid_t pid, Elf_Addr addr);

void
pt_rm_breakpoint (pid_t pid, long old_opcode);

void
pt_rewind_eip (pid_t pid, int i);

void
pt_set_eip (pid_t pid, Elf_Addr addr);

#endif /* #ifndef _ptrace_wrap_h_ */
