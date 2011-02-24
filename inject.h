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

#ifndef _inject_h_
#define _inject_h_

struct code_injection {
    unsigned char *code;    /* machine code           */
    unsigned int pidx;      /* index of address patch */
    unsigned int length;    /* length of machine code */
    unsigned int nsparms;   /* # of stack parameters  */
    unsigned int returns;   /* 0: no        1: yes    */
    size_t size;            /* size of machine code   */
};

void
patch_addr (unsigned char* buf, long addr);

struct code_injection*
inject_build_start (Elf_Addr addr);

struct code_injection*
inject_build_end (Elf_Addr addr);

struct code_injection*
inject_build_prjpln (Elf_Addr addr, char* name);

struct code_injection*
inject_build_checkplan (Elf_Addr addr, char* proj, char* plan);

int
inject (pid_t pid, Elf_Addr addr, struct code_injection* inject);

void
inject_destroy (struct code_injection* inj);

#endif /* #ifndef _inject_h_ */
