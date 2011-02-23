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

#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include "context.h"
#include "plans.h"
#include "tuner_util.h"
#include "tuner_genetic.h"

//-------------------------------------------
#define MIN_GPU_MEM 0.90f
#define GENERATIONS 10
#define POPULATION  20
#define ELITE       0.25f
//-------------------------------------------

#define DEBUG

// -- State Macros -----------------------
#define SAVE_STATE(state_ptr)            \
    (ctx->tuner_state = (void*)state_ptr) 

#define RESTORE_STATE(state_ptr)         \
    (state_ptr = ctx->tuner_state)        
// ---------------------------------------

// NOTES
// 
// * The 1st generation is not entirely random.  All candidates are required
//   to have a minimum amount of (programmer defined) GPU memory utilization.
//   This is because we want to force candidates away from the region of the
//   search space consisting of heavy pinned host memory usage.
//
// * It is possible that alloc_mem() will be unable to place all entries into
//   GPU memory that the candidate desires.  In this case, alloc_mem() will
//   automatically move a GPU allocation to pinned host memory and modify
//   entry->loc.  This is an environment induced mutation and should be
//   checked for after every alloc_mem().


#if defined (DEBUG)
    FILE* fp;
#endif

//------------------------------------------------------------------------------
// HELPERS
//------------------------------------------------------------------------------
void
sort (candidate** c, int n)
{
    int i, j;
    double tmp_fit;
    unsigned long long tmp_DNA;
    for (j=0; j<(n-1); j++) {
        for (i=0; i<(n-(1+j)); i++) {
            if (c[i]->fit > c[i+1]->fit) {
                tmp_fit = c[i+1]->fit;
                tmp_DNA = c[i+1]->DNA;

                c[i+1]->fit = c[i]->fit;
                c[i+1]->DNA = c[i]->DNA;

                c[i]->fit = tmp_fit;
                c[i]->DNA = tmp_DNA;
            }
        }
    }
}


candidate*
immaculate_conception (CUZMEM_CONTEXT ctx)
{
    unsigned long long DNA;
    unsigned int loc, gpu_mem_free, gpu_mem_total, gpu_mem_req;
    unsigned int creating = 1;
    cuzmem_plan* entry = ctx->plan;
    candidate* c = (candidate*)malloc (sizeof(candidate));

    cuMemGetInfo (&gpu_mem_free, &gpu_mem_total);

    while (creating) {
        c->DNA = rand();
        c->DNA = c->DNA << 32;
        c->DNA = c->DNA + rand();
        c->DNA &= generate_mask(ctx->num_knobs);

        // gpu memory utilization
        gpu_mem_req = 0;
        entry = ctx->plan;
        while (entry != NULL) {
            if (entry->gold_member) {
                loc = (c->DNA >> entry->id) & 0x0001;
                gpu_mem_req += entry->size * loc;
            }
            entry = entry->next;
        }

        // check constraint
        if (gpu_mem_req > gpu_mem_free * MIN_GPU_MEM) {
            creating = 0;
        }
    }

    c->fit = 0;
    return c;
}

//------------------------------------------------------------------------------
// GENETIC TUNER
//------------------------------------------------------------------------------
cuzmem_plan*
cuzmem_tuner_genetic (enum cuzmem_tuner_action action, void* parm)
{
    candidate** c;
    CUZMEM_CONTEXT ctx = get_context();

    // =========================================================================
    //  TUNER START
    // =========================================================================
    if (CUZMEM_TUNER_START == action) {

        if (ctx->tune_iter == 0) {
#if defined (DEBUG)
            fp = fopen("scores.txt", "w");
#endif
            // allocate array of candidates
            c = (candidate**)malloc (sizeof(candidate*) * POPULATION);
            SAVE_STATE (c);
        }
        else if (ctx->tune_iter % POPULATION == 1) {
            RESTORE_STATE (c);

            // time to magic up the first generation
            if (ctx->tune_iter == 1) {
                int i;

                for (i=0; i<POPULATION; i++) {
                    c[i] = immaculate_conception (ctx);
                }

                SAVE_STATE (c);
            }

            // time to breed the next generation
            else {
                int i,mom,dad;
                unsigned long long mix,mix_b;
                int num_elite = POPULATION * ELITE;
                candidate** b = (candidate**) malloc (sizeof(candidate*) * POPULATION);

                sort (c, POPULATION);

#if defined (DEBUG)
                fprintf (fp, "Generation %i\n", ctx->tune_iter / POPULATION);
                for (i=0; i<POPULATION; i++) {
                    fprintf (fp, "c: %i  f: %f  dna: %llu\n", i, c[i]->fit, c[i]->DNA);
                }
                fprintf (fp, "\n");
                fflush (fp);
#endif
                // construct buffer
                for (i=0; i<POPULATION; i++) {
                    b[i] = (candidate*)malloc (sizeof(candidate));
                    b[i]->fit = 0;
                }

                // pick out the "alpha-males"
                for (i=0; i<num_elite; i++) {
                    b[i]->DNA = c[i]->DNA;
                    b[i]->fit = c[i]->fit;
                }

                // remaining are offspring of the top 50th percentile
                for (i=num_elite; i<(POPULATION); i++) {
                    // choose parents (no asexual reproduction)
                    do {
                        mom = rand() % (POPULATION / 2);
                        dad = rand() % (POPULATION / 2);
                    } while (mom == dad);

                    // determine DNA mix
                    mix = rand();
                    mix = mix << 32;
                    mix = mix + rand();
                    mix &= generate_mask(ctx->num_knobs);
                    mix_b = mix;

                    // mate the parents
                    b[i]->DNA = c[mom]->DNA & mix; 
                    mix  = (~mix) & generate_mask(ctx->num_knobs);
                    b[i]->DNA |= c[dad]->DNA & mix;
                }

                // make offspring the new generation
                SAVE_STATE (b);
                for (i=0; i<POPULATION; i++) {
                    free (c[i]);
                }
                free (c);

            }
        }

        // start timing the iteration
        ctx->start_time = get_time ();

        // Return value currently has no meaning
        return NULL;
    }
    // =========================================================================
    //  TUNER LOOKUP
    // =========================================================================
    else if (CUZMEM_TUNER_LOOKUP == action) {
        // parm: pointer to size of allocation
        size_t size = *(size_t*)(parm);

        CUresult ret;
        unsigned int i, loc, c_num;
        cuzmem_plan* entry = NULL;

        // default 0th tuning iteration handling
        if (ctx->tune_iter == 0) {
            return zeroth_lookup_handler (ctx, size);
        }

        // handle looping allocations & get current entry
        if (loopy_entry (ctx, &entry, size)) {
            return loopy_entry_handler (entry, size);
        }

        RESTORE_STATE (c);

        // retrieve candidate's location for this allocation
        c_num = (ctx->tune_iter - 1) % POPULATION;
        loc = (c[c_num]->DNA >> entry->id) & 0x0001;

        // assign to entry and perform allocation
        entry->loc = loc;
        ret = alloc_mem (entry, size);

        // check for environment induced mutation
        if (entry->loc != loc) {
            // clear mutated bit
            c[c_num]->DNA &= ~(0x0001 << entry->id);

            // set mutated bit
            c[c_num]->DNA |= entry->loc << entry->id;
            SAVE_STATE (c);
        }

        // prepare for next iteration
        ctx->current_knob++;
        return entry;
    }
    // =========================================================================
    //  TUNER END
    // =========================================================================
    else if (CUZMEM_TUNER_END == action) {
        double time;
        unsigned int c_num, i;

        if (ctx->tune_iter == 0) {
            if (zeroth_end_handler (ctx)) {
                // everything fits in GPU memory, returning ends search
                return NULL;
            }

            // genetic search specific: compute # of tune iterations
            ctx->tune_iter_max = (unsigned long long)(GENERATIONS * POPULATION);

            max_iteration_handler (ctx);
            return NULL;
        }

        RESTORE_STATE (c);

        // put exec time into active candidate's fitness
        c_num = (ctx->tune_iter - 1) % POPULATION;
        c[c_num]->fit = get_time() - ctx->start_time;

        // if we are done
        if (ctx->tune_iter >= ctx->tune_iter_max) {
            cuzmem_plan* entry = ctx->plan;

            // leave tuning mode
            ctx->op_mode = CUZMEM_RUN;

            // make the best final candidate the plan
            sort (c, POPULATION);
            while (entry != NULL) {
                entry->loc = (c[0]->DNA >> entry->id) & 0x0001;
                entry = entry->next;
            }
            write_plan (ctx->plan, ctx->project_name, ctx->plan_name);

#if defined (DEBUG)
            fprintf (fp, "Final Generation\n");
            for (i=0; i<POPULATION; i++) {
                fprintf (fp, "c: %i  f: %f  dna: %llu\n", i, c[i]->fit, c[i]->DNA);
            }
            fclose (fp);
#endif
            // and free the candidates
            for (i=0; i<POPULATION; i++) {
                free (c[i]);
            }
            free (c);
        }

        return NULL;
    }
}

