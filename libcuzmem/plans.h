/*  This file is part of libcuzmem
    Copyright (C) 2011  James A. Shackleford

    libcuzmem is free software: you can redistribute it and/or modify
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

#ifndef _plans_h_
#define _plans_h_

#include <stdlib.h>
#include <cuda.h>

// -- Plan structure -----------------------------
typedef struct cuzmem_plan_entry cuzmem_plan;
struct cuzmem_plan_entry
{
    int id;
    size_t size;
    int loc;           // 0: pinned cpu, 1: gpu global
    int inloop;        // 0: false     , 1: true
    int first_hit;     // 0: false     , 1: true
    int gold_member;   // 0: false     , 1: true

    void* gpu_pointer;
    void* cpu_pointer;
    CUdeviceptr gpu_dptr;

    cuzmem_plan* next;
};
// -----------------------------------------------


#if defined __cplusplus
extern "C" {
#endif

size_t
rm_whitespace (char *str);

cuzmem_plan*
read_plan (char *project_name, char *plan_name);

void
write_plan (cuzmem_plan* plan, char *project_name, char *plan_name);

int
check_plan (const char* project_name, const char* plan_name);

#if defined __cplusplus
};
#endif


#endif // #ifndef _plans_h_
