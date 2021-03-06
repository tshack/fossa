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

#include "fossa.h"
#include "options.h"
#include "ptrace_wrap.h"
#include "elf_tools.h"
#include "child_tools.h"
#include "inject.h"
#include "hash.h"

// TODO: Add for-loop detection to step_till_ret()
//       for programmers who like to put large
//       cuda memory initialization loops right
//       there in main()  (cough... CUDA SDK)


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
    long eip;
    unsigned char opcode;

    printf ("Single-Stepping child.\n");
    for (i=0; i<20; i++) {
        eip = pt_get_eip (pid);
        pt_peek (pid, eip, &opcode, 1);
        fprintf (stderr, "0x%08x: %lx\n", (unsigned int)eip, (unsigned long)opcode);
        pt_singlestep (pid);
//        fprintf (stderr, "0x%08x\n", eip);
    }

}
#endif


void
set_mode (struct fossa_options* opt, int planless)
{
    // NOTE
    // planless = 0     ( a plan exists)
    // planless = 1     (no plan exists)
    // opt->mode = 0    (CUZMEM_RUN)
    // opt->mode = 1    (CUZMEM_TUNE)

    // no plan and run mode?  no sir!
    if (planless && (opt->mode == 0)) {
        printf (
            "---------------------------------------------------------------------------\n"
            "  fossa does not have an optimized memory configuration for `%s'\n"
            "  Performance may be poor.  Run fossa in tune mode (--tune) to optimize \n"
            "---------------------------------------------------------------------------\n\n",
            opt->child_prg
        );
        sleep (1);
        opt->tuner = 0;     // use "no tune" tuner
        opt->mode = 1;      // enter tuning mode
    }
    // we want to tune and we already have a plan
    else if (!planless && (opt->mode == 1)) {
        opt->mode = 1;
    }
    // are planless, want to tune?  ok
    // not planless, want to run? ok, same thing
    else {
        opt->mode = planless;
    }
}


void
init_main (pid_t pid, Elf_Addr *main_start)
{
    int found=0;
    long old_opcode, eip;
    unsigned char tmp_opcode[8];

    // set breakpoint @ start of main() prologue
    old_opcode = pt_set_breakpoint (pid, *main_start);

    // run to breakpoint
    pt_continue (pid);

    // remove the breakpoint
    pt_rm_breakpoint (pid, old_opcode);

#if _arch_x86_64_
    (*main_start)++;
#endif
}


Elf_Addr
step_till_ret (pid_t pid)
{
    unsigned char opcode;
    long inst = 0x00;
    long old_inst;
    long eip;

    while (opcode != 0xc3) {
        eip = pt_get_eip (pid);
        inst = pt_get_instruction (pid);
        opcode = (unsigned char)inst;
//        fprintf (stderr, "%lx: %lx\n", eip, opcode);
//        sleep (1);

        // next opcode is call (don't step into, step over)
        // the call instruction is 5 bytes
        if (opcode == 0xe8) {
//            fprintf (stderr, "stepping over\n");
            pt_stepover (pid, 5);
        }
        // also deal with calls to register contents
        // these are usually dlsym calls such as: call *%eax
        // these call instructions are just 2 bytes
        else if (opcode == 0xff) {
            opcode = (unsigned char)(inst >> 8);
            if ( (opcode == 0xd0) ||    /*  call *%eax   */
                 (opcode == 0xd3) ||    /*  call *%ebx   */
                 (opcode == 0xd1) ||    /*  call *%ecx   */
                 (opcode == 0xd2) ||    /*  call *%edx   */
                 (opcode == 0x10) ||    /*  call *(%eax) */
                 (opcode == 0x13) ||    /*  call *(%ebx) */
                 (opcode == 0x11) ||    /*  call *(%ecx) */
                 (opcode == 0x12) ||    /*  call *(%edx) */
                 (opcode == 0x18) ||    /* lcall *(%eax) */
                 (opcode == 0x1b) ||    /* lcall *(%ebx) */
                 (opcode == 0x19) ||    /* lcall *(%ecx) */
                 (opcode == 0x1a)       /* lcall *(%edx) */
               )
            {
//                fprintf (stderr, "stepping over\n");
                pt_stepover (pid, 2);
            }
        }
        else if (opcode != 0xc3) {
            pt_singlestep (pid);
        }
        else if (opcode == 0xc3) {
            // replace ret with int3
            eip = pt_get_eip (pid);
            pt_set_breakpoint (pid, eip);
            return eip;
        }
        else {
            fprintf (stderr, "execution path tracer is confused (?!) quitting...\n\n");
            exit (1);
        }
    }

    return 0;
}


struct toolbox*
create_toolbox (pid_t pid)
{
    struct toolbox* tbox = malloc (sizeof (struct toolbox));

    printf ("fossa: Searching child's symbol table for instruments... ");
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
        printf ("  Please make sure libcuzmem.so (included with fossa) is in your\n"
                "  library path and is locatable by ld.so\n\n");
        exit (1);
    }

    printf ("success.\n");

    return tbox;
}


int
main (int argc, char* argv[], char* envp[])
{
    pid_t pid;
    int i, iter, planless;
    char* plan_hash;
    int tuning = 1;
    char project[FILENAME_MAX];
    Elf_Addr main_start, ret_addr;
    struct fossa_options opt;
    struct toolbox* tbox;
    struct code_injection *inj_start, *inj_end,
                          *inj_set_project, *inj_set_plan,
                          *inj_check_plan, *inj_set_tuner;


    opt.mode = 0;       // make run mode the default mode
    opt.tuner = 1;      // genetic tuner is default
    opt.oom_adj = 0;

    // initialization
    parse_cmdline (&opt, argc, argv);
    elf_get_func (opt.child_argv[0], "main", &main_start, NULL);
    pid = child_fork (opt.child_argv, envp, opt.oom_adj);
    init_main (pid, &main_start);
    tbox = create_toolbox (pid);
    plan_hash = hash (&opt);

    // setup project directory for this child program
    sprintf (project, "fossa/%s", opt.child_prg);

    // launch check_plan injection to see if this program has a plan
    inj_check_plan  = inject_build_checkplan (tbox->check_plan, project, plan_hash);
    planless = inject (pid, main_start, inj_check_plan);

    // adjust the operation mode based on plan status
    set_mode (&opt, planless);

    // build the rest of the injections
    inj_start       = inject_build_start     (tbox->start, opt.mode);
    inj_end         = inject_build_end       (tbox->end);
    inj_set_project = inject_build_prjpln    (tbox->set_project, project);
    inj_set_plan    = inject_build_prjpln    (tbox->set_plan, plan_hash);
    inj_set_tuner   = inject_build_settuner  (tbox->set_tuner, opt.tuner);
    free (plan_hash);

    // set the plan, the project, and the tuner
    inject (pid, main_start, inj_set_project);
    inject (pid, main_start, inj_set_plan);
    inject (pid, main_start, inj_set_tuner);


    iter=0;
    while (tuning) {
        if (opt.mode == 1 && opt.tuner != 0) {
            printf ("fossa: Tuning Iteration: %03i\n", iter);
            printf ("----------------------------\n", iter);
        }

        // inject the start()
        inject (pid, main_start, inj_start);

        // resume the child
        // it will run until it hits the int3 @ end of main()
        if (iter == 0) {
            ret_addr = step_till_ret (pid);
        } else {
            pt_continue (pid);
        }

        // hit int3 @ end of main()
        // move PC back to start of main() so that we can
        // be sure we have enough room to inject code :-)
        pt_set_eip (pid, main_start);

        // now, we inject the end() call
        tuning = inject (pid, main_start, inj_end);

        if (!tuning) {
            // we are done.
            // remove the int3 @ the end of main()
            if (opt.mode == 1 && opt.tuner != 0) {
                printf ("fossa: Tuning Complete\n");
            }

            // jump back just after the breakpoint
            pt_set_eip (pid, ret_addr+1);

            // restore main() ret instruction & rewind eip
            pt_rm_breakpoint (pid, 0xc3);

            // let main() return
            pt_detach (pid);
        }

        iter++;
    }


    inject_destroy (inj_start);
    inject_destroy (inj_end);
    free (tbox);

    return 0;
}

