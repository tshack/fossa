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

#include <stdlib.h>
#include <stdio.h>
#include <string.h> 
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>

#include "fossa.h"
#include "ptrace_wrap.h"

void
pt_attach (pid_t pid)
{
    int s;

    if ((ptrace (PTRACE_ATTACH, pid, NULL, NULL)) < 0) {
        fprintf (stderr, "Critical Failure: ptrace attach unsuccessful.\n");
        exit(1);
    }

    waitpid (pid, NULL, WUNTRACED);
}


void
pt_detach (pid_t pid)
{
    if (ptrace (PTRACE_DETACH, pid, NULL, NULL) < 0) {
        fprintf (stderr, "Critical Failure: ptrace detach unsuccessful.\n");
        exit(1);
    }
}


void
pt_allow_trace (void)
{
    ptrace (PTRACE_TRACEME, NULL, NULL);
}

void
pt_continue (pid_t pid)
{
    int s;
    long tmp;
    struct user_regs_struct regs;

    if ((ptrace (PTRACE_CONT, pid, NULL, NULL)) < 0) {
        if (errno) {
            fprintf (
                stderr,
                "CRITICAL FAILURE: ptrace continue unsuccessful (%i)\n",
                errno
            );
        }
        exit(1);
    }

    // block until child is stopped
    do {
        // because our we are asking the child to do some pretty outrageous
        // memory acrobatics, there is a good chance on low memory systems that
        // the OOM will kill the child process if its "badness score" gets high
        // enough.  so, we should check for that...
        waitpid (pid, &s, WNOHANG);
        if ( WIFSIGNALED (s) ) {
            if ( WTERMSIG (s) == 9 ) {
                fprintf (stderr, "CRITICAL FAILURE: child process received SIGKILL\n");
                fprintf (stderr, "(Probably from Linux kernel OOM service due to insufficient system memory)\n");
                exit (1);
            }
        }
        ptrace (PTRACE_GETREGS, pid, NULL, &regs) ;
    } while
#if _arch_i386_
        ( ptrace (PTRACE_PEEKDATA, pid, regs.eip, NULL) == -1 );
#elif _arch_x86_64_
        ( ptrace (PTRACE_PEEKDATA, pid, regs.rip, NULL) == -1 );
#endif

}


void 
pt_peek (pid_t pid, Elf_Addr addr, void *vptr, unsigned int len)
{
    int i, count;
    long word;
    unsigned long *ptr = (unsigned long *)vptr;

    i = count = 0;

    while (count < len) {
        word = ptrace (PTRACE_PEEKTEXT, pid, addr+count, NULL);

        // ptrace returns -1 on errors... but we also could have peeked
        // a -1 from memory.  So, some special checking is needed.
        if (word == -1) {
            if (errno) {
                fprintf (stderr, "CRITICAL ERROR: pt_peek failed (%i)\n",
                        errno);
                exit (1);
            }
        }

        count += sizeof(Elf_Addr);
        ptr[i++] = word;
    }
}


void 
pt_poke (pid_t pid, Elf_Addr addr, void *vptr, unsigned int len)
{
    int i , count;
    long word;

    i = count = 0;

    while (count < len) {
        memcpy (&word, vptr+count, sizeof(word));
        word = ptrace (PTRACE_POKETEXT, pid, addr+count, word);
        count += sizeof (Elf_Addr);
    }
}

// Given an address into the child's address space,
// this function will "stringify" up to 256 characters
// starting at the specifed address.
char *
pt_get_str (pid_t pid, Elf_Addr addr)
{
        long ptr[256];
        int len = 256;
        char* string = (char*)malloc (sizeof(char) * 256);

        pt_peek (pid, addr, ptr, len);

        bzero (string, sizeof(char) * 256);

        strncpy (string, (char*)ptr, strlen((char*)ptr));
        return string;
}

void
pt_singlestep (pid_t pid)
{
    int s;
    long word;
    struct user_regs_struct regs;

    word = ptrace (PTRACE_SINGLESTEP, pid, NULL, NULL);

    if (word != 0) {
        fprintf (stderr, "CRITICAL ERROR: single stepping failed!\n");
        exit (1);
    }

    // block until child is stopped
    do {
        ptrace (PTRACE_GETREGS, pid, NULL, &regs) ;
    } while
#if _arch_i386_
        ( ptrace (PTRACE_PEEKDATA, pid, regs.eip, NULL) == -1 );
#elif _arch_x86_64_
        ( ptrace (PTRACE_PEEKDATA, pid, regs.rip, NULL) == -1 );
#endif

}

void
pt_get_regs (pid_t pid, struct user_regs_struct* regs)
{
    ptrace (PTRACE_GETREGS, pid, NULL, regs);
}


void
pt_set_regs (pid_t pid, struct user_regs_struct* regs)
{
    ptrace (PTRACE_SETREGS, pid, NULL, regs);
}

long
pt_set_breakpoint (pid_t pid, Elf_Addr addr)
{
    long word;

    word = ptrace (PTRACE_PEEKTEXT, pid, addr, NULL);
    if (word == -1) {
        if (errno) {
            fprintf (stderr,
                    "CRITICAL ERROR: pt_set_breakpoint failed (%i)\n", errno);
            exit (1);
        }
    }
    ptrace (PTRACE_POKETEXT, pid, addr, 0xcc);

    return word;
}

void
pt_rm_breakpoint (pid_t pid, long old_opcode)
{
    long eip;

    pt_rewind_eip (pid, 1);
    eip = pt_get_eip (pid);
    ptrace (PTRACE_POKETEXT, pid, eip, old_opcode);
}

void
pt_rewind_eip (pid_t pid, int i)
{
    struct user_regs_struct regs;

    ptrace (PTRACE_GETREGS, pid, NULL, &regs);
    
#if _arch_i386_
    regs.eip -= i;
#elif _arch_x86_64_
    regs.rip -= i;
#endif

    ptrace (PTRACE_SETREGS, pid, NULL, &regs);
}

void
pt_set_eip (pid_t pid, Elf_Addr addr)
{
    struct user_regs_struct regs;

    ptrace (PTRACE_GETREGS, pid, NULL, &regs);
    
#if _arch_i386_
    regs.eip = addr;
#elif _arch_x86_64_
    regs.rip = addr;
#endif

    ptrace (PTRACE_SETREGS, pid, NULL, &regs);
}

long
pt_get_eip (pid_t pid)
{
    struct user_regs_struct regs;

    ptrace (PTRACE_GETREGS, pid, NULL, &regs);
    
#if _arch_i386_
    return regs.eip;
#elif _arch_x86_64_
    return regs.rip;
#endif

}

long
pt_get_instruction (pid_t pid)
{
    long eip = pt_get_eip (pid);
    long inst;

    pt_peek (pid, eip, &inst, 1);

    return inst;
}
