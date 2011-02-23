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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <cuda.h>
#include <driver_types.h>
#include <sys/time.h>
#include <sys/types.h>

#include "libcuzmem.h"
#include "context.h"
#include "plans.h"
#include "tuner_exhaust.h"
#include "tuner_genetic.h"

//#define DEBUG

// some non-API function declarations I wanted to keep out of libcuzmem.h
CUresult alloc_mem (cuzmem_plan* entry, size_t size);
double get_time();

//------------------------------------------------------------------------------
// CUDA RUNTIME REPLACEMENTS
//------------------------------------------------------------------------------

cudaError_t
cudaMalloc (void **devPtr, size_t size)
{
    CUresult ret;
    cuzmem_plan *entry = NULL;
    CUZMEM_CONTEXT ctx = get_context();

    *devPtr = NULL;

    // Decide what to do with current knob
    if (CUZMEM_RUN == ctx->op_mode) {
        // 1) Load plan for this project
        entry = ctx->plan;

        // 2) Lookup malloc type for this knob & allocate
        while (entry != NULL) {
            if (entry->id == ctx->current_knob) {
                ret = alloc_mem (entry, size);
                *devPtr = entry->gpu_pointer;
                break;
            }
            entry = entry->next;
        }

        // Knob id exceeds those found in plan... must be in a malloc/free loop
        if (*devPtr == NULL) {
            // Look for a free()ed "inloop" marked plan entry 
            entry = ctx->plan;
            while (1) {
                if (entry == NULL) {
                    fprintf (stderr,"libcuzmem: unable to deduce inloop allocation from plan!\n");
                    exit (1);
                }
                if ((entry->inloop == 1)         &&
                    (entry->gpu_pointer == NULL) &&
                    (entry->size == size))
                {
                        ret = alloc_mem (entry, size);
                        if (ret != CUDA_SUCCESS) {
                            fprintf (stderr, "libcuzmem: inloop alloc_mem() failed [%i]\n", ret);
                        }
                        *devPtr = entry->gpu_pointer;
                        break;
                }
                entry = entry->next;
            }
        } else {
            // Don't increment current_knob for inloop allocations,
            // they are knobs that we have already counted!
            ctx->current_knob++;
        }
    }
    else if (CUZMEM_TUNE == ctx->op_mode) {
        // Lookup current_knob in plan draft.
        // An entry is returned describing the malloc action taken
        // NOTE: NULL is returned if no malloc occured
        entry = ctx->call_tuner (CUZMEM_TUNER_LOOKUP, &size);
        if (entry == NULL) {
            ret = CUDA_ERROR_NOT_INITIALIZED;
        } else {
            *devPtr = entry->gpu_pointer;

            if (ctx->tune_iter == 0) {
                ctx->allocated_mem += size;
            }
        }
    }

    // Morph CUDA Driver return codes into CUDA Runtime codes
    switch (ret)
    {
    case CUDA_SUCCESS:
        return (cudaSuccess);
    case CUDA_ERROR_DEINITIALIZED:
    case CUDA_ERROR_NOT_INITIALIZED:
    case CUDA_ERROR_INVALID_CONTEXT:
    case CUDA_ERROR_INVALID_VALUE:
    case CUDA_ERROR_OUT_OF_MEMORY:
    default:
        return (cudaErrorMemoryAllocation);
    }

}

cudaError_t
cudaFree (void *devPtr)
{
    CUresult ret;
    CUZMEM_CONTEXT ctx = get_context();
    cuzmem_plan *entry = NULL;

    // -------------------------------------------------------------------------
    // if tuning, determine the largest aggregate allocation during 0th cycle
    if (CUZMEM_TUNE == ctx->op_mode) {
        if (ctx->tune_iter == 0) {
            // candidate largest alloc set, mark'em up as gold members
            if (ctx->allocated_mem > ctx->most_mem_allocated) {
                ctx->most_mem_allocated = ctx->allocated_mem;
                entry = ctx->plan;
                while (entry != NULL) {
                    if (entry->gpu_pointer != NULL) {
                        entry->gold_member = 1;
                    } else {
                        entry->gold_member = 0;
                    }
                    if (entry->gpu_pointer == devPtr) {
                        ctx->allocated_mem -= entry->size;
                    }
                    entry = entry->next;
                }
            }
            // just another free during the 0th iteration
            else {
                entry = ctx->plan;
                while (entry != NULL) {
                    if (entry->gpu_pointer == devPtr) {
                        ctx->allocated_mem -= entry->size;
                        break;
                    }
                    entry = entry->next;
                }
            }
        }
    }
    // -------------------------------------------------------------------------

    // Lookup plan entry for this gpu pointer
    entry = ctx->plan;
    while (1) {
        if (entry == NULL) {
            fprintf (stderr, "libcuzmem: attempt to free invalid pointer (%p).\n", devPtr);
            exit (1);
        }
        if (entry->gpu_pointer == devPtr) {
            break;
        }
        entry = entry->next;
    }

    // Was it pinned cpu memory or real gpu memory?
    if (entry->cpu_pointer == NULL) {
        // real gpu memory
        ret = cuMemFree (entry->gpu_dptr);
        entry->gpu_pointer = NULL;
    } else {
        // pinned cpu memory
        ret = cuMemFreeHost (entry->cpu_pointer);
        entry->gpu_pointer = NULL;
        entry->cpu_pointer = NULL;
    }

    // Morph CUDA Driver return codes into CUDA Runtime codes
    switch (ret)
    {
    case CUDA_SUCCESS:
        return (cudaSuccess);
    case CUDA_ERROR_DEINITIALIZED:
    case CUDA_ERROR_NOT_INITIALIZED:
        return (cudaErrorInitializationError);
    case CUDA_ERROR_INVALID_CONTEXT:
    case CUDA_ERROR_INVALID_VALUE:
    case CUDA_ERROR_OUT_OF_MEMORY:
    default:
        return (cudaErrorInvalidDevicePointer);
    }
}



//------------------------------------------------------------------------------
// CUDA RUNTIME REPLACEMENT HELPERS
//------------------------------------------------------------------------------

// handles actual process of host memory allocation
CUresult
alloc_mem_host (cuzmem_plan* entry, size_t size)
{
    CUresult ret;
    CUdeviceptr dev_mem;
    void* host_mem = NULL;

    // allocate pinned host memory
    ret = cuMemHostAlloc ((void **)&host_mem, size,
            CU_MEMHOSTALLOC_PORTABLE |
            CU_MEMHOSTALLOC_DEVICEMAP |
            CU_MEMHOSTALLOC_WRITECOMBINED);
    if (ret != CUDA_SUCCESS) {
        fprintf (stderr, "libcuzmem: failed to pin cpu memory [%i]\n", ret);
        return CUDA_ERROR_INVALID_VALUE;
    };
    ret = cuMemHostGetDevicePointer (&dev_mem, host_mem, 0);

    // record in entry for cudaFree() later on
    if (ret == CUDA_SUCCESS) {
        entry->cpu_pointer = (void *)host_mem;
        entry->gpu_pointer = (void *)dev_mem;
        entry->gpu_dptr = dev_mem;
    } else {
        fprintf (stderr, "libcuzmem: failed to map pinned cpu memory\n");
    }

#if defined (DEBUG)
        fprintf (stderr, "libcuzmem: alloc %i B (pinned) [%p]\n", (int)size, entry->gpu_pointer);
#endif

    return ret;
}


// handles actual process of device memory allocation
CUresult
alloc_mem_device (cuzmem_plan* entry, size_t size)
{
    CUresult ret;
    CUdeviceptr dev_mem;

    // allocate gpu global memory
    ret = cuMemAlloc (&dev_mem, (unsigned int)size);

    // record in entry entry for cudaFree() later on
    if (ret == CUDA_SUCCESS) {
        entry->gpu_pointer = (void *)dev_mem;
        entry->gpu_dptr = dev_mem;
#if defined (DEBUG)
        fprintf (stderr, "libcuzmem: alloc %i B (global) [%p]\n", (int)size, entry->gpu_pointer);
#endif
    } else {
        ret = alloc_mem_host (entry, size);
        entry->loc = 0;
    }

    return ret;
}


// wrapper for memory allocation handlers
CUresult
alloc_mem (cuzmem_plan* entry, size_t size)
{
    CUresult ret;

    if (entry->loc == 1) {
        ret = alloc_mem_device (entry, size);
    }
    else if (entry->loc == 0) {
        ret = alloc_mem_host (entry, size);
    }
    else {
        // unspecified memory location
        fprintf (stderr, "libcuzmem: entry specifed malloc to neither pinned nor global memory!\n");
        exit (1);
    }

    return ret;
}


// simply returns the time
double
get_time ()
{
    struct timeval tv;
    gettimeofday (&tv, 0);
    return ((double) tv.tv_sec) + ((double) tv.tv_usec) / 1000000.;
}


//------------------------------------------------------------------------------
// FRAMEWORK FUNCTIONS
//------------------------------------------------------------------------------

// Called at start of each plan invocation
void
cuzmem_start (enum cuzmem_op_mode m, CUdevice cuda_dev)
{
    CUZMEM_CONTEXT ctx = get_context();

    // we handle CUDA context stuff here
    if (ctx->tune_iter == 0) {
        CUresult ret;

        cuInit(0);

        // 1st: if the CUDA runtime has already created a context,
        //      we will simply latch on to it
        ret = cuCtxAttach (&(ctx->cuda_context), 0);

        if (ret != CUDA_SUCCESS) {
            // 2nd: if a CUDA runtime generated context does not
            //      exist, we will simply create one
            cuCtxCreate (&(ctx->cuda_context), CU_CTX_SCHED_AUTO | CU_CTX_MAP_HOST, cuda_dev);
        }
    }

    // This state info is modified for all tuners.
    ctx->current_knob = 0;
    ctx->op_mode = m;

    if (CUZMEM_RUN == ctx->op_mode) {
        ctx->plan = read_plan (ctx->project_name, ctx->plan_name);
    }
    // Invoke Tuner's "Start of Plan" routine.
    else if (CUZMEM_TUNE == ctx->op_mode) {
        ctx->call_tuner (CUZMEM_TUNER_START, NULL);
    }
    else {
        fprintf (stderr, "libcuzmem: unknown operation mode specified!\n");
    }
}


// Called at end of each plan invocation
enum cuzmem_op_mode
cuzmem_end ()
{
    CUZMEM_CONTEXT ctx = get_context();

    // Ask the selected Tuner Engine what to do.
    if (CUZMEM_TUNE == ctx->op_mode) {
        ctx->call_tuner (CUZMEM_TUNER_END, NULL);
        ctx->tune_iter++;
    }

    if (CUZMEM_RUN == ctx->op_mode) {
        // we are done with the CUDA context.  if it
        // was created by us, we need to destry it.
        if (ctx->cuda_context != NULL) {
            cuCtxDestroy (ctx->cuda_context);
        }
    }

    // Return this back to calling program so that the
    // framework will know what to do next: next iteration
    // or stop iterating. [ can be modified by call_tuner()
    return ctx->op_mode;
}



//------------------------------------------------------------------------------
// USER INTERFACE FUNCTIONS
//------------------------------------------------------------------------------

// Used to select/define CUZMEM project
void
cuzmem_set_project (char* project)
{
    CUZMEM_CONTEXT ctx = get_context();

    strcpy (ctx->project_name, project);
}


// Used to select/define CUZMEM plan
void
cuzmem_set_plan (char* plan)
{
    CUZMEM_CONTEXT ctx = get_context();

    strcpy (ctx->plan_name, plan);
}


// Used to select Tuning Engine
void
cuzmem_set_tuner (enum cuzmem_tuner t)
{
    CUZMEM_CONTEXT ctx = get_context();

    switch (t)
    {
    case CUZMEM_EXHAUSTIVE:
        ctx->call_tuner = cuzmem_tuner_exhaust;
        break;
    case CUZMEM_GENETIC:
    default:
        ctx->call_tuner = cuzmem_tuner_genetic;
    }
}

// Used to see if a specific plan exists for a given project
int
cuzmem_check_plan (const char* project, const char* plan)
{
    return check_plan (project, plan);
}

// Used to set the mimimum GPU global memory utilization
// a plan must satisfy in order to be accepted
void
cuzmem_set_minimum (float p)
{
    CUZMEM_CONTEXT ctx = get_context();

    ctx->gpu_mem_percent = p;
}
