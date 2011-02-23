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
#include <unistd.h>
#include <string.h>
#include <link.h>           /* for struct link_map */
#include <sys/user.h>

#include "fossa.h"
#include "ptrace_wrap.h"
#include "child_tools.h"
#include "inject.h"

// ref: http://tldp.org/LDP/LG/issue85/sandeep.html

//#define DEBUG

struct toolbox {
    Elf_Addr start;
    Elf_Addr end;
    Elf_Addr set_project;
    Elf_Addr set_plan;
    Elf_Addr set_tuner;
    Elf_Addr check_plan;
};

#if defined (DEBUG)
void
dbg_step_print (pid_t pid, int i)
{
    long old_eip;    
    unsigned char opcode;
    struct user_regs_struct child_regs;

    printf ("Single-Stepping child.\n");
    for (i=0; i<20; i++) {
#if _arch_i386_
        old_eip = child_regs.eip;
#elif _arch_x86_64_
        old_eip = child_regs.rip;
#endif
        pt_singlestep (pid);
        pt_get_regs (pid, &child_regs);
#if _arch_i386_
        pt_peek (pid, child_regs.eip, &opcode, 1);
        fprintf (stderr, "0x%08x: %02x\n", child_regs.eip, opcode);
//        fprintf (stderr, "0x%08x\n", child_regs.eip);
#elif _arch_x86_64_
        pt_peek (pid, child_regs.rip, &opcode, 1);
        fprintf (stderr, "0x%08x: %lx\n", child_regs.rip, opcode);
//        fprintf (stderr, "0x%08x\n", child_regs.rip);
#endif
    }

}
#endif



// this function sets a breakpoint @ the first opcode **inside** of main()
// [i.e. after the function preamble] and runs the child to the breakpoint.
// once @ the breakpoint, we replace int3 at the breakpoint with the orig
// instruction and rewind the program counter to just before the breakpoint.
long
init_child (pid_t pid, Elf_Addr *main_start, Elf_Addr *main_len)
{
    int status, found = 0;
    unsigned int pushes = 0;
    long old_opcode_s, old_opcode_e;
    unsigned char tmp_opcode[8];
    struct user_regs_struct child_regs;
    Elf_Addr main_end;

    printf ("Attached to child process: %d\n", pid);    
    printf ("Found main() @ 0x%lx\n", *main_start);
    printf ("main() length: %i\n", *main_len);
    printf ("main() end:    %lx\n", *main_start + *main_len);

    // set a breakpoint @ start of main()
    old_opcode_s = pt_set_breakpoint (pid, *main_start);

    // resume the child -- run to start breakpoint
    pt_continue (pid);

    // remove breakpoint
    pt_rewind_eip (pid, 1);
    pt_get_regs (pid, &child_regs);
#if _arch_i386_
    pt_poke (pid, child_regs.eip, &old_opcode_s, 1);
    fprintf (stderr, "Paused child @ main() [0x%lx]\n", child_regs.eip);
#elif _arch_x86_64_
    pt_poke (pid, child_regs.rip, &old_opcode_s, 1);
    fprintf (stderr, "Paused child @ main() [0x%lx]\n", child_regs.rip);
#endif

    // now single step until we find what (at least) "looks like"
    // the end of the main() function prologue
    while (!found) {
        pt_get_regs (pid, &child_regs);
#if _arch_i386_
        pt_peek (pid, child_regs.eip, tmp_opcode, 1);
#elif _arch_x86_64_
        pt_peek (pid, child_regs.rip, tmp_opcode, 1);
#endif

        // count pushes.  we can make a good guess of where the
        // main() epilogue starts based on the number of pushes
        // found in the prologue
        if ( (tmp_opcode[0] == 0x55) ||     /* push %ebp */
             (tmp_opcode[0] == 0x56) ||     /* push %esi */
             (tmp_opcode[0] == 0x53)        /* push %ebx */

           ) { pushes++; }

        // we are looking for a subtraction from the stack pointer
        if (tmp_opcode[1] == 0xec ||
            tmp_opcode[2] == 0xec)
        {
           pt_singlestep (pid);
            pt_get_regs (pid, &child_regs);
#if _arch_i386_
            fprintf (stderr, "main() prologue ends @ 0x%lx\n", child_regs.eip);
            *main_len -= (child_regs.eip - *main_start) + 1;
            *main_start = child_regs.eip;
#elif _arch_x86_64_
            fprintf (stderr, "main() prologue ends @ 0x%lx\n", child_regs.rip);
            *main_len -= (child_regs.rip - *main_start) + 1;
            *main_start = child_regs.rip;
#endif
            found = 1;
        } else {
            pt_singlestep (pid);
        }
    }

    // this is purely empirically derived...
    if (pushes == 1) {
        // for this case, usually only %ebp was pushed.  it seems that for
        // this, gcc uses leave, ret for an epilogue
        *main_len -= 1;
    }
#if _arch_x86_64_
    else if (pushes == 2) {
        *main_len -= 2;

        if ( tmp_opcode[0] == 0x48 &&
             tmp_opcode[1] == 0x81)
        {
            *main_len -= 7;
        }
    }
#endif
    else {
        // gcc pushed something other can %ebp when this happens, it pops each
        // off individually in the epilogue... it seems
        *main_len -= (pushes + 2);
        // length of sub opcode used to adjust stack
        // this allows us to *infer* the length of the manditory
        // add %esp instruction in the epilogue
        if (tmp_opcode[0] == 0x81) {
            *main_len -= 6;
        }
    }

    printf ("main() length: %i\n", *main_len);
    printf ("main() end:    %lx\n", *main_start + *main_len);

    // set a breakpoint @ end of main()
    main_end = *main_start + *main_len;
    old_opcode_e = pt_set_breakpoint (pid, main_end);
    printf ("Set Breakpoint @ end of main() [0x%lx]\n", main_end);

    // return the old end of main() opcode so that we can
    // exit main() later when we are finished
    return old_opcode_e;
}


struct toolbox*
create_toolbox (pid_t pid)
{
    struct toolbox* tbox = malloc (sizeof (struct toolbox));

    fprintf (stderr, "Searching child's symbol table for instruments... ");
    tbox->start       = child_dlsym (pid, "cuzmem_start"       , "libcuzmem.so");
    tbox->end         = child_dlsym (pid, "cuzmem_end"         , "libcuzmem.so");
    tbox->set_project = child_dlsym (pid, "cuzmem_set_project" , "libcuzmem.so");
    tbox->set_plan    = child_dlsym (pid, "cuzmem_set_plan"    , "libcuzmem.so");
    tbox->set_tuner   = child_dlsym (pid, "cuzmem_set_tuner"   , "libcuzmem.so");
    tbox->check_plan  = child_dlsym (pid, "cuzmem_check_plan"  , "libcuzmem.so");

    if ( (!tbox->start)       ||
         (!tbox->end)         ||
         (!tbox->set_project) ||
         (!tbox->set_plan)    ||
         (!tbox->set_tuner)   ||
         (!tbox->check_plan) )
    {
        printf ("FAILED!\n\n");
        exit (1);
    }

    printf ("success.\n");

    printf ("  * tbox->start : 0x%lx\n", tbox->start);
    printf ("  * tbox->end   : 0x%lx\n", tbox->end);
    
    return tbox;
}


int
main (int argc, char* argv[], char* envp[])
{
    pid_t pid;
    int i, correctly_invoked = 0, tuning = 1;
    long int main_start, main_len;
    struct toolbox* tbox;
    struct code_injection *inj_start, *inj_end;
    struct user_regs_struct child_regs;
    char old_opcode;
    char child_parms[259];


    if (argc < 2) {
        printf ("usage: %s program\n" , argv[0]);
        exit (1);
    }

    strcpy (child_parms, "");
    for (i=2; i<argc; i++) {
        strcat (child_parms, argv[i]);
        strcat (child_parms, " ");
    }
    printf ("child_parms: %s\n", child_parms);

    // --------------------------------------------------------------------------
    // make sure the instrumentation library was LD_PRELOADED
    for (i=0; envp[i]; i++) {
        if (strstr (envp[i], "LD_PRELOAD=./libcuzmem.so")) {
            correctly_invoked = 1;
        }
    }
    if (!correctly_invoked) {
        fprintf (stderr, "%s cannot be ran directly.\n"
                         "please run using included script\n\n",
                         file_from_path(argv[0]));
        exit (0);
    }
    // --------------------------------------------------------------------------

    // initialization
    child_get_main (argv[1], &main_start, &main_len);
    pid = child_fork (argv[1], &argv[1]);
    old_opcode = init_child (pid, &main_start, &main_len);
    tbox = create_toolbox (pid);

    // build the injections
    inj_start = inject_build_start (tbox->start);
    inj_end   = inject_build_end   (tbox->end);

    i=0;
    while (tuning) {
        printf ("Tuning Iteration: %i\n", i++);

        // inject the start()
        inject (pid, main_start, inj_start);

        // resume the child
        // it will run until it hits the int3 @ end of main()
//        fprintf (stderr, "Resuming child.\n");
        pt_continue (pid);

        // hit int3 @ end of main()
        // move PC back to start of main() so that we can
        // be sure we have enough room to inject code :-)
        pt_set_eip (pid, main_start);

        // now, we inject the end() call
        tuning = inject (pid, main_start, inj_end);

        if (!tuning) {
            // we are done.
            // remove the int3 @ the end of main()
            printf ("Tuning Complete\n");

            // jump back to the end
            pt_set_eip (pid, main_start + main_len);

            // restore the last instruction in main()
            pt_get_regs (pid, &child_regs);
#if _arch_i386_
            pt_poke (pid, child_regs.eip, &old_opcode, 1);
#elif _arch_x86_64_
            pt_poke (pid, child_regs.rip, &old_opcode, 1);
#endif

            // let main() return
            pt_continue (pid);
        }
    }


    inject_destroy (inj_start);
    inject_destroy (inj_end);
    free (tbox);

    return 0;
}

