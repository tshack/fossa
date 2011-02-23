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
#include <fcntl.h>
#include <errno.h>
#include <link.h>
#include <sys/user.h>
#include <sys/stat.h>

#include "fossa.h"
#include "ptrace_wrap.h"
#include "child_tools.h"

char*
file_from_path (char* full_path)
{
    char* file_name = NULL;

    // Get the last occurance of '/'
    if (full_path) {
        file_name = strrchr (full_path, '/') + 1;
    }

    return file_name;
}


pid_t
child_fork (char* prg, char* parms)
{
	char *path = prg;
    char *name = strrchr(path, '/');
    pid_t child_pid;

    if (name) {
        name = name + 1;        
    } else {
        name = path;
    }

    switch (child_pid = fork()) {
        case -1:
            perror ("fork()");
            exit (1);
        case 0: 
            pt_allow_trace ();
//            execl (path, name, parms, (char*)NULL);
            execv (path, parms);
            fprintf (stderr, "CRITICAL ERROR: could not load target \"%s\"\n", prg);
            exit (1);
    }
    waitpid (child_pid, NULL, 0);

    // The child is stopped @ this point due to the execl() call
    // (received SIGTRAP)

    return child_pid;
}


void
child_get_main (char* elf_file, long int *main_start, long int *main_len)
{
    int i, fd_elf = -1;
    u_char* base = NULL;
    struct stat elf_stat;
    Elf_Ehdr      *ehdr   = NULL;
    Elf_Phdr      *phdr   = NULL;
    Elf_Shdr      *shdr   = NULL;
    Elf_Sym       *sym    = NULL;
    char* strtable = NULL;
    char* sym_name = NULL;
    size_t cur_size = 0;
    size_t sym_size = 0;

    
    fd_elf = open (elf_file, O_RDONLY);
    if (fd_elf == -1) {
        fprintf (stderr, "Could not open %s: %s\n", elf_file, strerror(errno));
        exit (1);
    }

    if (fstat (fd_elf, &elf_stat) == -1) {
        fprintf (stderr, "Could not stat %s: %s\n", elf_file, strerror(errno));
        exit (1);
    }

    base = (u_char *)calloc (sizeof(u_char), elf_stat.st_size);
    if (!base) {
        fprintf (stderr, "No enough memory\n");
        close (fd_elf);
        exit (1);
    }

    if (read (fd_elf, base, elf_stat.st_size) != elf_stat.st_size) {
        fprintf (stderr, "Eror while copying file into memory: %s\n", strerror(errno));
        free (base);
        close (fd_elf);
        exit (1);
    }

    close (fd_elf);

    // We now have the ELF header
    ehdr = (Elf_Ehdr *)base;

    // Get the program and section headers
    phdr = (Elf_Phdr *)(base + ehdr->e_phoff);
    shdr = (Elf_Shdr *)(base + ehdr->e_shoff);

    // Get offset to the string table (.shstrtab)
    // .shstrtab holds the ELF section names
    strtable = (char*)(base + shdr[ehdr->e_shstrndx].sh_offset);

    // Cycle through section headers
    for (i=0; i<ehdr->e_shnum; i++) {
        if (shdr[i].sh_type == SHT_DYNSYM) {
            sym = (Elf_Sym*)(base + shdr[i].sh_offset);
            sym++;

            sym_size = shdr[i].sh_entsize;
            cur_size +=sym_size;

            do {
#if _arch_i386_
                if (ELF32_ST_TYPE(sym->st_info) != STT_SECTION) {
#elif _arch_x86_64_
                if (ELF64_ST_TYPE(sym->st_info) != STT_SECTION) {
#endif
                    sym_name = (base + shdr[shdr[i].sh_link].sh_offset) + sym->st_name;
                    if (!strcmp ("main", sym_name)) {
                        *main_start = sym->st_value;
                        *main_len   = sym->st_size;

                        // Skip function prologue
#if 0
                        *main_start += 9;
                        *main_len -= 9;

                        // Don't count function epilogue
                        *main_len -= 2;
#endif

                        free (base);
                        return;
                    }
                }

                cur_size += sym_size;
                sym++;
            } while (cur_size < shdr[i].sh_size);
        }
    }
}


// Get the address of the Global Offset Table within
// a child process's memory space
Elf_Addr
child_get_got (pid_t pid)
{
    Elf_Ehdr      *ehdr   = malloc(sizeof(Elf_Ehdr));
    Elf_Phdr      *phdr   = malloc(sizeof(Elf_Phdr));
    Elf_Dyn       *dyn    = malloc(sizeof(Elf_Dyn));
    Elf_Word      got;
    Elf_Addr      phdr_addr, dyn_addr;

    // The ELF header starts at the beginning of .text, which
    // is always located at 0x08048000 on 32-bit x86 systems
    // and 0x00400000 on 64-bit x86 systems.
    pt_peek (pid, BASE_TEXT, ehdr, sizeof(Elf_Ehdr));

    // Compute starting address of program headers and copy them into phdr
    phdr_addr = BASE_TEXT + ehdr->e_phoff;
    pt_peek (pid, phdr_addr, phdr, sizeof(Elf_Phdr));

    // Find the PT_DYNAMIC section
    while (phdr->p_type != PT_DYNAMIC) {
        phdr_addr += sizeof(Elf_Phdr);
        pt_peek (pid, phdr_addr, phdr, sizeof(Elf_Phdr));
//        fprintf (stderr, "phdr->p_type: 0x%08x\n", phdr->p_type);
    }        

    // Search the PT_DYNAMIC section for the GOT address
    pt_peek (pid, phdr->p_vaddr, dyn, sizeof(Elf_Dyn));
    dyn_addr = phdr->p_vaddr;
    while (dyn->d_tag != DT_PLTGOT) {
        dyn_addr += sizeof(Elf_Dyn);
        pt_peek (pid, dyn_addr, dyn, sizeof(Elf_Dyn));
    }

    // Return starting address of Global Offset Table
    got = (Elf_Word)dyn->d_un.d_ptr;

    free (ehdr);
    free (phdr);
    free (dyn);

    return got;
}


// Get the address of the link_map within a child process's memory space
// (see: /usr/include/link.h)
struct link_map*
child_get_linkmap (pid_t pid)
{
    struct link_map *map_head = malloc(sizeof(struct link_map));
    Elf_Addr map_addr;
    Elf_Word got;

    // Get address of Global Offset Table in child
    got = child_get_got (pid);

    // (4 bytes)>>GOT[0]      linked list pointer used by the dynamic loader 
    // link_map >>GOT[1]      pointer to the relocation table for this module 
    //            GOT[2]      pointer to the resolver code (in ld-linux.so.2)
    //            ...         function call helpers, 1 per imported function 
    got += sizeof (Elf_Addr);

    // Read the first link_map entry
    pt_peek (pid, (unsigned long)got, &map_addr, sizeof (Elf_Addr));
    pt_peek (pid, map_addr, map_head, sizeof(struct link_map));

    return map_head;
}


// For a given link_map entry, this function will resolve the # of symbols
// (nchains) and the addresses of the associated string and symbols tables
// (strtab & symtab).
//
// Note: link_map->l_ld contains the address of the shared library's
// dynamic sections (DT_*), which is where we search for this stuff.
struct lib_map*
child_get_lib (pid_t pid, struct link_map *entry)
{
    unsigned long addr, addr_nchains;
    Elf_Dyn *dyn = malloc (sizeof(Elf_Dyn));
    struct lib_map *lib = malloc (sizeof(struct lib_map));

    // save library's base address in child's virtual memory map
    lib->base_addr = entry->l_addr;

    // now search through dynamic sections for what we want
    addr = (unsigned long)entry->l_ld;
    pt_peek (pid, addr, dyn, sizeof(Elf_Dyn));

    while (dyn->d_tag) {
        switch (dyn->d_tag) {
            case DT_HASH:
                addr_nchains = dyn->d_un.d_ptr+4;
                pt_peek (pid, addr_nchains, &lib->num_syms, sizeof (lib->num_syms));
                break;
            case DT_STRTAB:
                lib->strtab = dyn->d_un.d_ptr;
                break;
            case DT_SYMTAB:
                lib->symtab = dyn->d_un.d_ptr;
                break;
            default:
                break;
        }

        addr += sizeof (Elf_Dyn);
        pt_peek (pid, addr, dyn, sizeof (Elf_Dyn));
    }

    free(dyn);

    return lib;
}


// Get the address of a symbol within a library that
// exists in the linkmap.
unsigned long
child_get_sym ( int pid, char* sym_name, struct lib_map* lib)
{
    int i;
    char *str;
    Elf_Sym *sym = malloc (sizeof(Elf_Sym));

    i = 0;
    while (i < lib->num_syms) {
        // get the next symbol from the symbol table
        pt_peek (pid, lib->symtab+(i*sizeof(Elf_Sym)), sym, sizeof(Elf_Sym));
        i++;
        
        // is this symbol a function ?
        if (ELF32_ST_TYPE (sym->st_info) != STT_FUNC) {
            continue;
        }

        // yes, get its name
        str = pt_get_str (pid, lib->strtab + sym->st_name);
//        fprintf (stderr, "sym->st_name: %s\n", str);
    
        // does this name match the name we are looking for ?
        if (strncmp (str, sym_name, strlen(sym_name))) {
            // no, just free str
            free (str);
        } else {
            // yes, return (base_addr + offset)
            free (str);
            return (lib->base_addr + sym->st_value);
        }
            
    }

    // symbol not found
    return 0;
}   

struct link_map*
child_search_linkmap (pid_t pid, char *lib_name)
{
    char full_libname[256];
    char* short_libname;
    struct link_map *entry;

    entry = child_get_linkmap (pid);

    // cycle link_map until we find our library
    while (entry->l_next) {
        // entry = entry->l_next;
        pt_peek (pid, (unsigned long)entry->l_next, entry, sizeof(struct link_map));

        // full_libname = entry->l_name;
        pt_peek (pid, (unsigned long)entry->l_name, full_libname, sizeof(full_libname));

        // don't process "empty" library names
        if (*full_libname == '\0') {
            continue;
        }

        // remove the path from the library, get just the library filename
        short_libname = file_from_path (full_libname);

        // did we find the library?
        if (strncmp (short_libname, lib_name, strlen(lib_name))) {
            continue;
        } else {
            return entry;
        }
    }

    // could not find library in linkmap
    return NULL;
}

// Given a symbol *name* and library *name*, this function
// will return the virtual address of the desired symbol
unsigned long
child_dlsym (int pid, char *sym_name, char *lib_name)
{
    struct link_map *entry;
    struct lib_map* lib;
    Elf_Addr sym;

    // search link_map for desired library name
    entry = child_search_linkmap (pid, lib_name);

    // get library info (strtab, symtab, num_syms)
    lib = child_get_lib (pid, entry);

    // Get the symbol
    sym = child_get_sym (pid, sym_name, lib);

    free (lib);

    return sym;
}

