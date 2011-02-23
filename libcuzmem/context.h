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

#ifndef _context_h_
#define _context_h_

#include <stdio.h>
#include <cuda.h>
#include <sys/types.h>
#include "libcuzmem.h"
#include "plans.h"

#define MAX_CONTEXTS  256

// -- Context structure --------------------------
// NOTE: a libcuzmem context is bound to thread id
typedef struct cuzmem_context_instance cuzmem_context;
struct cuzmem_context_instance
{
    unsigned int id;
    char plan_name[MAX_CONTEXTS];
    char project_name[MAX_CONTEXTS];
    unsigned int tune_iter;
    unsigned long long num_knobs;
    unsigned long long current_knob;
    unsigned long long tune_iter_max;
    enum cuzmem_op_mode op_mode;
    cuzmem_plan *plan;
    double start_time;
    unsigned long best_time;
    unsigned long long best_plan;
    unsigned int gpu_mem_percent;
    size_t allocated_mem;       // only valid 0th cycle tune
    size_t most_mem_allocated;
    CUcontext cuda_context;
    cuzmem_plan* (*call_tuner)(enum cuzmem_tuner_action, void*);
    void* tuner_state;
};
typedef cuzmem_context* CUZMEM_CONTEXT;
// -----------------------------------------------

// -- Contexts -----------------------------------
extern cuzmem_context* context[];
extern pid_t context_lut[];
// -----------------------------------------------



#if defined __cplusplus
extern "C" {
#endif

cuzmem_context*
create_context ();

cuzmem_context*
get_context ();

void
destroy_context ();

unsigned int
get_context_id ();

// Stuff from libcuzmem that doesn't need to be seen
// by developers
CUresult
alloc_mem (cuzmem_plan* entry, size_t size);

double
get_time ();

#if defined __cplusplus
}
#endif


#endif // #ifndef _context_h_
