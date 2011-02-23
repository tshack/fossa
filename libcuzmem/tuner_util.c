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

#include <cuda.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include "context.h"
#include "plans.h"

// TODO: should be CMake generated
#define WORD_SIZE 8

// returns a bit mask of n contiguous bits
unsigned long long
generate_mask (unsigned int n)
{
    unsigned long long tmp = ULLONG_MAX;

    tmp = tmp << (64 - n);
    tmp = tmp >> (64 - n);

    return tmp;
}

// returns number of bits required to express n combinations
unsigned int
num_bits (unsigned long long n)
{
    unsigned int exp = 0;
    unsigned long long p = 2;
    while (p < n && p != 0) {
        ++exp;
        p *= 2;
    }
    return exp + 1;
}

// detect if requested malloc is recurring within a single
// optimization iteration loop
unsigned int
detect_inloop (cuzmem_plan** entry, size_t size)
{
    while (*entry != NULL) {
        if (((*entry)->size == size) && ((*entry)->gpu_pointer == NULL)) {
            // found a malloc/free loop within tuning loop
            (*entry)->inloop = 1;
            return 1;
        }
        *entry = (*entry)->next;
    }

    return 0;
}

// checks if the requested malloc is known to reoccur within
// a single optimization iteration
unsigned int
check_inloop (cuzmem_plan** entry, size_t size)
{
    while (*entry != NULL) {
        if (((*entry)->size == size)        &&
            ((*entry)->gpu_pointer == NULL) &&
            ((*entry)->inloop == 1)) {
            // found a matching (& unused) inloop entry
            return 1;
        }
        *entry = (*entry)->next;
    }

    return 0;
}

// finds entry in plan for the current knob
// Returns:
//   0 if found
//   1 if not found
unsigned int
find_current_entry (CUZMEM_CONTEXT ctx, cuzmem_plan** entry)
{
    *entry = ctx->plan;
    while (*entry != NULL) {
        if ((*entry)->id == ctx->current_knob) {
            return 0;
        }
        *entry = (*entry)->next;
    }

    return 1;
}

// standard 0th iteration logic
// * powers through the first iteration by whatever means necessary
// * attempts to detect "loopy" allocations
// * builds the (0th generation) plan draft
// * determines the search space
// * returns entry (if NULL, we failed somehow - probably too little host mem)
cuzmem_plan*
zeroth_lookup_handler (CUZMEM_CONTEXT ctx, size_t size)
{
    if (ctx->tune_iter == 0) {
        CUresult ret = CUDA_SUCCESS;
        cuzmem_plan* entry = ctx->plan;
        int loopy = detect_inloop (&entry, size);

        if (loopy) {
            ret = alloc_mem (entry, size);
            if (ret != CUDA_SUCCESS) {
                // Note, cudaMalloc() will report a NULL return value
                // from call_tuner(LOOKUP) as cudaErrorMemoryAllocation
                entry = NULL;
            }
        } else {
            entry = (cuzmem_plan*) malloc (sizeof(cuzmem_plan));
            entry->id = ctx->current_knob;
            entry->size = size;
            entry->loc = 1;
            entry->inloop = 0;
            entry->first_hit = 1;
            entry->cpu_pointer = NULL;
            entry->gpu_pointer = NULL;

            ret = alloc_mem (entry, size);
            if (ret != CUDA_SUCCESS) {
                // not enough CPU memory: return failure
                free (entry);
                entry = NULL;
            }

            // Insert successful entry into plan draft
            entry->next = ctx->plan;
            ctx->plan = entry;

            ctx->current_knob++;
        }

        return entry;
    }
}

// standard 0th iteration logic
// * checks if cpu-pinned memory is necessary at all
// * if pinned memory is necessary, saves num_knobs (full search space)
// returns:
//   1 if everything fits in GPU global memory
//   0 if we must continue searching
unsigned int
zeroth_end_handler (CUZMEM_CONTEXT ctx)
{
    if (ctx->tune_iter == 0) {
        unsigned int all_global = 1;
        cuzmem_plan* entry = ctx->plan;

        // check all entries for pinned host memory usage
        while (entry != NULL) {
            if (entry->loc != 1) {
                all_global = 0;
                break;
            }
            entry = entry->next;
        }

        // quit now if everything fits in gpu memory
        if (all_global) {
            printf ("libcuzmem: auto-tuning complete.\n");
            ctx->op_mode = CUZMEM_RUN;
            write_plan (ctx->plan, ctx->project_name, ctx->plan_name);
            return 1;
        }

        // if everything didn't fit, size up the search space
        ctx->num_knobs = ctx->current_knob + 1;

        if (ctx->num_knobs > sizeof(unsigned long long) * WORD_SIZE) {
            fprintf (stderr, "libcuzmem: allocation symbol limit exceeded!\n");
            exit(0);
        }

        return 0;
    }
}

// Is the entry loopy?
// * if YES: two things can happen
//     -- 1) first_hit is TRUE, we check to make sure we have the
//           correct entry by searching for current_knob & then
//           we toggle first_hit and return FALSE
//     -- 2) first_hit is FALSE, we return TRUE
// * if NO: get current entry and return FALSE
unsigned int
loopy_entry (CUZMEM_CONTEXT ctx, cuzmem_plan** entry, size_t size)
{
    *entry = ctx->plan;
    unsigned int loopy = check_inloop (entry, size);

    if (loopy) {
        if ((*entry)->first_hit == 1) {
            // first_hit is TRUE, make sure we are
            // looking at the correct entry.
            find_current_entry (ctx, entry);

            // is this entry known to be loopy?
            if ((*entry)->inloop) {
                (*entry)->first_hit = 0;
                return 0;
            } else {
                fprintf (stderr, "libcuzmem: critical loopy detection error\n");
            }
        } else {
            // first_hit is FALSE
            return 1;
        }
    } else {
        find_current_entry (ctx, entry);
        return 0;
    }
}


// this handles loopy allocations that are on their 2nd+ hit
cuzmem_plan*
loopy_entry_handler (cuzmem_plan* entry, size_t size)
{
    CUresult ret;
    ret = alloc_mem (entry, size);
    if (ret != CUDA_SUCCESS) {
        // error, return null
        return NULL;
    } else {
        // success
        return entry;
    }
}


// to be called within CUZMEM_TUNER_END
// stops tuning process if maximum # of tuning
// iterations have been reached.  Writes out best
// plan discovered during search.
void
max_iteration_handler (CUZMEM_CONTEXT ctx)
{
    // have we hit the max # of allowed iterations?
    if (ctx->tune_iter >= ctx->tune_iter_max) {
        cuzmem_plan* entry = ctx->plan;

        // if so, stop iterating
        printf ("libcuzmem: auto-tuning complete.\n");
        ctx->op_mode = CUZMEM_RUN;

        // ...and write out the best plan
        while (entry != NULL) {
            entry->loc = (ctx->best_plan >> entry->id) & 0x0001;
            entry = entry->next;
        }
        write_plan (ctx->plan, ctx->project_name, ctx->plan_name);
    } else {
        // not finished, so get ready for next tuning iteration
        ctx->current_knob = 0;
    }

}

// printf ("%s", binary(n));
const char*
binary (unsigned long long x)
{
    static char b[9];
    b[0] = '\0';

    unsigned long long z;
    for (z = 0x8000000000000000; z > 0; z >>= 1) {
        strcat(b, ((x & z) == z) ? "1" : "0");
    }

    return b;
}
