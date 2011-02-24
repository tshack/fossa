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


#ifndef _child_tools_h_
#define _child_tools_h_

#include "fossa.h"

// library map
struct lib_map {
    int num_syms;
    Elf_Addr symtab;
    Elf_Addr strtab;
    Elf_Addr base_addr;
};

char*
file_from_path (char* full_path);

pid_t
child_fork (char* prg, char** parms);

Elf_Addr
child_get_got (pid_t pid);

struct link_map*
child_get_linkmap (pid_t pid);

struct lib_map*
child_get_lib (pid_t pid, struct link_map *entry);

unsigned long
child_get_sym (pid_t pid, char* sym_name, struct lib_map* lib);

struct link_map*
child_search_linkmap (pid_t pid, char *lib_name);

unsigned long
child_dlsym (pid_t pid, char *sym_name, char *lib_name);

#endif /* #ifndef _child_tools_h_ */
