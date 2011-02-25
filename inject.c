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
#include <sys/user.h>

#include "fossa.h"
#include "ptrace_wrap.h"
#include "inject.h"

//#define DEBUG

#if defined (DEBUG)
void
dbg_print_mem (pid_t pid, Elf_Addr addr, unsigned int len)
{
    unsigned int i;
    unsigned char* tmp = malloc (sizeof(unsigned char) * len);

    pt_peek (pid, addr, tmp, len);
    for (i=0; i<len; i++) {
        printf ("%x ", tmp[i]);
    }
    printf ("\n\n");
}
#endif

void
patch_addr (unsigned char* buf, long addr)
{
    *(buf+0) = addr;
    *(buf+1) = addr >> 8;
    *(buf+2) = addr >> 16;
    *(buf+3) = addr >> 24;

#if _arch_x86_64_
    *(buf+4) = addr >> 32;
    *(buf+5) = addr >> 40;
    *(buf+6) = addr >> 48;
    *(buf+7) = addr >> 56;
#endif
}


struct code_injection*
inject_build_start (Elf_Addr addr, unsigned int mode)
{
    struct code_injection *inject;

    inject = malloc (sizeof (struct code_injection));

    inject->returns = 0;
#if _arch_i386_
    inject->length = 23;
    inject->pidx = 16;
    inject->nsparms = 2;
#elif _arch_x86_64_
    inject->length = 23;
    inject->pidx = 2;
    inject->nsparms = 0;
#endif

    inject->size = inject->length * sizeof (unsigned char);
    inject->code = malloc (inject->size);

#if _arch_i386_
    memcpy (inject->code, 
        "\xc7\x44\x24\x04\x00\x00\x00"  /* movl   $0x0, 0x4(%esp)   */
        "\x00"
        "\xc7\x04\x24\x01\x00\x00\x00"  /* movl   $0x1, (%esp)      */
        "\xbb\x78\x56\x34\x12"          /* mov    $0x12345678, %ebx */
        "\xff\xd3"                      /* call   *%ebx             */
        "\xcc",                         /* int3                     */
        inject->size
    );
    *(inject->code + 11) = (unsigned char)(mode & 0xFF);
#elif _arch_x86_64_
    memcpy (inject->code, 
        "\x48\xb8"                      /* mov $0x1234567812345678, %rax */
        "\x78\x56\x34\x12"
        "\x78\x56\x34\x12"
        "\xbe\x00\x00\x00\x00"          /* mov    $0x0, %esi             */
        "\xbf\x01\x00\x00\x00"          /* mov    $0x1, %edi             */
        "\xff\xd0"                      /* callq  *%rax                  */
        "\xcc",                         /* int3                          */
        inject->size
    );
    *(inject->code + 16) = (unsigned char)(mode & 0xFF);
#endif

    patch_addr (inject->code + inject->pidx, addr);

    return inject;
}


struct code_injection*
inject_build_end (Elf_Addr addr)
{
    struct code_injection *inject;

    inject = malloc (sizeof (struct code_injection));

    inject->returns = 1;        /* does injection return a value? */
#if _arch_i386_                 /****** i386 CODE ATTRIBUTES ******/
    inject->length = 8;         /* length of injection code       */
    inject->pidx = 1;           /* patch index (for call address) */
    inject->nsparms = 0;        /* # of stack parameters          */
#elif _arch_x86_64_             /******* x64 CODE ATTRIBUTES ******/
    inject->length = 13;        /* length of injection code       */
    inject->pidx = 2;           /* patch index (for call address) */
    inject->nsparms = 0;        /* # of stack parameters          */
#endif                          /**********************************/

    inject->size = inject->length * sizeof (unsigned char);
    inject->code = malloc (inject->size);

#if _arch_i386_
    memcpy (inject->code, 
        "\xbb\x78\x56\x34\x12"          /* mov    $0x12345678, %ebx */
        "\xff\xd3"                      /* call   *%ebx             */
        "\xcc",                         /* int3                     */
        inject->size
    );
#elif _arch_x86_64_
    memcpy (inject->code, 
        "\x48\xb8"                      /* mov $0x1234567812345678, %rax */
        "\x78\x56\x34\x12"
        "\x78\x56\x34\x12"
        "\xff\xd0"                      /* callq  *%rax                  */
        "\xcc",                         /* int3                          */
        inject->size
    );
#endif

    patch_addr (inject->code + inject->pidx, addr);

    return inject;
}


void
inject_destroy (struct code_injection* inj)
{
    free (inj->code);
    free (inj);
}


// cuzmem_set_project () and cuzmem_set_plan() share the
// exact same calling convention, so we can resuse this
// for both
struct code_injection*
inject_build_prjpln (Elf_Addr addr, char* name)
{
    struct code_injection *inject;
    unsigned int str_len = strlen (name)+1;

    inject = malloc (sizeof (struct code_injection));

    inject->returns = 0;        /* does injection return a value? */
#if _arch_i386_                 /****** i386 CODE ATTRIBUTES ******/
    inject->length = 14;        /* length of injection code       */
    inject->pidx = 7;           /* patch index (for call address) */
    inject->nsparms = 1;        /* # of stack parameters          */
#elif _arch_x86_64_             /******* x64 CODE ATTRIBUTES ******/
    inject->length = 17;        /* length of injection code       */
    inject->pidx = 6;           /* patch index (for call address) */
    inject->nsparms = 0;        /* # of stack parameters          */
#endif                          /**********************************/

    // leave room to tack the string onto the end of the machine code
    inject->size = (inject->length + str_len) * sizeof (unsigned char);
    inject->code = malloc (inject->size);

    // NOTE: in inject() I pass the program counter into eax/rax in
    //       order to make this simple
#if _arch_i386_
    memcpy (inject->code, 
        "\x8d\x40\x0e"                  /* lea    0x0e(%eax), %eax    */
        "\x89\x04\x24"                  /* mov    %eax, (%esp)        */
        "\xbb\x78\x56\x34\x12"          /* mov    $0x12345678, %ebx   */
        "\xff\xd3"                      /* call   *%ebx               */
        "\xcc",                         /* int3                       */
        inject->size
    );
#elif _arch_x86_64_
    memcpy (inject->code, 
        "\x48\x8d\x78\x12"              /* lea 0x11(%rax), %rdi          */
        "\x48\xb8"                      /* mov $0x1234567812345678, %rax */
        "\x78\x56\x34\x12"
        "\x78\x56\x34\x12"
        "\xff\xd0"                      /* callq  *%rax                  */
        "\xcc",                         /* int3                          */
        inject->size
    );
#endif

    patch_addr (inject->code + inject->pidx, addr);

    // because the function takes a string pointer, we need
    // to store the string somewhere... how about just after
    // the int3 opcode, eh?  :-)
    memcpy (inject->code + inject->length, name, str_len);
    inject->length += str_len;

    return inject;
}


struct code_injection*
inject_build_checkplan (Elf_Addr addr, char* proj, char* plan)
{
    struct code_injection *inject;
    unsigned int proj_len = strlen (proj)+1;
    unsigned int plan_len = strlen (plan)+1;
    unsigned int str_len = proj_len + plan_len;

    inject = malloc (sizeof (struct code_injection));

    inject->returns = 1;        /* does injection return a value? */
#if _arch_i386_                 /****** i386 CODE ATTRIBUTES ******/
    inject->length = 21;        /* length of injection code       */
    inject->pidx = 14;          /* patch index (for call address) */
    inject->nsparms = 2;        /* # of stack parameters          */
#elif _arch_x86_64_             /******* x64 CODE ATTRIBUTES ******/
    inject->length = 21;        /* length of injection code       */
    inject->pidx = 10;          /* patch index (for call address) */
    inject->nsparms = 0;        /* # of stack parameters          */
#endif                          /**********************************/

    // leave room to tack the string onto the end of the machine code
    inject->size = (inject->length + str_len) * sizeof (unsigned char);
    inject->code = malloc (inject->size);

    // NOTE: in inject() I pass the program counter into eax/rax in
    //       order to make this simple
#if _arch_i386_
    memcpy (inject->code, 
        "\x8d\x58\x15"                  /* lea    0x21(%eax), %ebx    */
        "\x8d\x40\xff"                  /* lea    0xff(%eax), %eax    */
        "\x89\x1c\x24"                  /* mov    %ebx, (%esp)        */
        "\x89\x44\x24\x04"              /* mov    %eax, 0x4(%esp)     */
        "\xbb\x78\x56\x34\x12"          /* mov    $0x12345678, %ebx   */
        "\xff\xd3"                      /* call   *%ebx               */
        "\xcc",                         /* int3                       */
        inject->size
    );
    *(inject->code + 5) = inject->length + proj_len;
#elif _arch_x86_64_
    memcpy (inject->code, 
        "\x48\x8d\x78\x16"              /* lea 0x16(%rax), %rdi          */
        "\x48\x8d\x70\xff"              /* lea 0xff(%rax), %rsi          */
        "\x48\xb8"                      /* mov $0x1234567812345678, %rax */
        "\x78\x56\x34\x12"
        "\x78\x56\x34\x12"
        "\xff\xd0"                      /* callq  *%rax                  */
        "\xcc",                         /* int3                          */
        inject->size
    );
    *(inject->code + 7) = inject->length + proj_len;
#endif

    patch_addr (inject->code + inject->pidx, addr);

    // tack strings onto end of machine code, project first
    memcpy (inject->code + inject->length, proj, proj_len);
    inject->length += proj_len;
    memcpy (inject->code + inject->length, plan, plan_len);
    inject->length += plan_len;

    return inject;
}


struct code_injection*
inject_build_settuner (Elf_Addr addr, unsigned int tuner)
{
    struct code_injection *inject;

    inject = malloc (sizeof (struct code_injection));

    inject->returns = 0;
#if _arch_i386_
    inject->length = 15;
    inject->pidx = 8; 
    inject->nsparms = 1;
#elif _arch_x86_64_
    inject->length = 18;
    inject->pidx = 2;
    inject->nsparms = 0;
#endif

    inject->size = inject->length * sizeof (unsigned char);
    inject->code = malloc (inject->size);

#if _arch_i386_
    memcpy (inject->code, 
        "\xc7\x04\x24\xff\x00\x00\x00"  /* movl   $0xff, (%esp)     */
        "\xbb\x78\x56\x34\x12"          /* mov    $0x12345678, %ebx */
        "\xff\xd3"                      /* call   *%ebx             */
        "\xcc",                         /* int3                     */
        inject->size
    );
    *(inject->code + 3) = (unsigned char)(tuner & 0xFF);
#elif _arch_x86_64_
    memcpy (inject->code, 
        "\x48\xb8"                      /* mov $0x1234567812345678, %rax */
        "\x78\x56\x34\x12"
        "\x78\x56\x34\x12"
        "\xbf\xff\x00\x00\x00"          /* mov    $0xff, %edi            */
        "\xff\xd0"                      /* callq  *%rax                  */
        "\xcc",                         /* int3                          */
        inject->size
    );
    *(inject->code + 11) = (unsigned char)(tuner & 0xFF);
#endif

    patch_addr (inject->code + inject->pidx, addr);

    return inject;
}



int
inject (pid_t pid, Elf_Addr addr, struct code_injection* inject)
{
    int i;
    int ret;
    struct user_regs_struct child_regs, tmp_regs;
    unsigned char *backup = malloc (inject->size);
    unsigned char *stack = NULL;

    // backup registers
    pt_get_regs (pid, &child_regs);

#if _arch_i386_
    // on i386 we use the stack for parameter
    // passing, so we must backup what we overwrite
    // TODO: Actually grow the stack for this in the event
    // the program has an empty (or too small) stack
    if (inject->nsparms != 0) {
        stack = malloc (inject->nsparms * sizeof(Elf_Addr));
        pt_peek (pid, child_regs.esp, stack, inject->nsparms * sizeof(Elf_Addr));
#if defined (DEBUG)
        printf ("Stack [esp 0x%08lx]:\n", child_regs.esp);
        dbg_print_mem (pid, child_regs.esp, inject->nsparms * sizeof(Elf_Addr));
#endif
    }
#endif

    // backup code we will be replacing
    pt_peek (pid, addr, backup, inject->length);

#if defined (DEBUG)
    printf ("Backed up:\n");
    dbg_print_mem (pid, addr, inject->length);
#endif

    // i tend to hide data at the end of injections
    // so, let's pass the program counter into eax
    // to make relative addressing easier
    pt_set_eax (pid, pt_get_eip (pid));

    // inject
    pt_poke (pid, addr, inject->code, inject->length);

#if defined (DEBUG)
    printf ("Injected:\n");
    dbg_print_mem (pid, addr, inject->length);
#endif

    // resume until child hits int3 @ end of injection
    pt_continue (pid);

    // Note: Child is paused from here until we pt_continue () it

    // get return value from injection (if it returns)
    if (inject->returns) {
#if _arch_i386_
        // i386 passes returns through eax
        pt_get_regs (pid, &tmp_regs);
        ret = (int)tmp_regs.eax;
#elif _arch_x86_64_
        // x86-64 passes returns through rax
        pt_get_regs (pid, &tmp_regs);
        ret = (int)tmp_regs.rax;
#endif
#if defined (DEBUG)
        fprintf (stderr, "Injection Returned: %i\n\n", ret);
#endif
    }

    // restore registers
    pt_set_regs (pid, &child_regs);

    // restore overwritten code
    pt_poke (pid, addr, backup, inject->size);

    // restore the stack on i386 (32-bit parm passing)
#if _arch_i386_
    if (inject->nsparms != 0) {
        pt_poke (pid, child_regs.esp, stack, inject->nsparms * sizeof(Elf_Addr));
    }
#endif


#if defined (DEBUG)
    printf ("Current image:\n");
    dbg_print_mem (pid, addr, inject->length);
#endif

    free (backup);
    free (stack);

    if (inject->returns) {
        return ret;
    } else {
        return 0;
    }
}
