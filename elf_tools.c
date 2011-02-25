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
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>

#include "fossa.h"

u_char*
elf_load (char* elf_file)
{
    int fd_elf = -1;
    u_char* elf_img = NULL;
    struct stat elf_stat;
    
    fd_elf = open (elf_file, O_RDONLY);
    if (fd_elf == -1) {
        fprintf (stderr, "Could not open %s: %i\n", elf_file, strerror(errno));
        exit (1);
    }

    if (fstat (fd_elf, &elf_stat) == -1) {
        fprintf (stderr, "Could not stat %s: %i\n", elf_file, strerror(errno));
        exit (1);
    }

    elf_img = (u_char *)calloc (sizeof(u_char), elf_stat.st_size);
    if (!elf_img) {
        fprintf (stderr, "No enough memory\n");
        close (fd_elf);
        exit (1);
    }

    if (read (fd_elf, elf_img, elf_stat.st_size) != elf_stat.st_size) {
        fprintf (stderr, "Error while copying file into memory: %i\n", strerror(errno));
        free (elf_img);
        close (fd_elf);
        exit (1);
    }

    close (fd_elf);

    return elf_img;
}


void
elf_get_func (char* elf_file, const char *func_name, Elf_Addr *func_start, Elf_Addr *func_len)
{
    int i;
    u_char* base = NULL;
    Elf_Ehdr      *ehdr   = NULL;
    Elf_Phdr      *phdr   = NULL;
    Elf_Shdr      *shdr   = NULL;
    Elf_Sym       *sym    = NULL;
    char* strtable = NULL;
    char* sym_name = NULL;
    size_t cur_size = 0;
    size_t sym_size = 0;

    base = elf_load (elf_file);

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
                    if (!strcmp (func_name, sym_name)) {
                        if (func_start != NULL) {
                            *func_start = sym->st_value;
                        }

                        if (func_len != NULL) {
                            *func_len   = sym->st_size;
                        }

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

