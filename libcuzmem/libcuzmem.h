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

#ifndef _cuzmem_h_
#define _cuzmem_h_

#include <cuda.h>
#include <driver_types.h>
#include <dlfcn.h>

// -- Tuning Engine stuff ------------------------
enum cuzmem_tuner_action {
    CUZMEM_TUNER_START,
    CUZMEM_TUNER_LOOKUP,
    CUZMEM_TUNER_END
};

enum cuzmem_tuner {
    CUZMEM_EXHAUSTIVE,
    CUZMEM_GENETIC
};
// -----------------------------------------------


// -- libcuzmem operation modes ------------------
enum cuzmem_op_mode {
    CUZMEM_RUN,
    CUZMEM_TUNE
};
// -----------------------------------------------

// -- My dlfcn Functions Macro  ------------------
#define MAKE_CUZMEM_API(f, ...)                  \
    f (__VA_ARGS__); typedef f##_cuzmem_t(__VA_ARGS__);  
// -----------------------------------------------


// -- Export symbols -----------------------------
#if defined __cplusplus
extern "C" {
#endif
    // Framework symbols
    MAKE_CUZMEM_API (
        void cuzmem_start,
            enum cuzmem_op_mode m,
            CUdevice cuda_dev
    );
    MAKE_CUZMEM_API (
        enum cuzmem_op_mode cuzmem_end,
            void
    );

    // User symbols
    MAKE_CUZMEM_API (
        void cuzmem_set_project,
            char* project
    );
    MAKE_CUZMEM_API (
        void cuzmem_set_plan,
            char* plan
    );
    MAKE_CUZMEM_API (
        int cuzmem_check_plan,
            const char* project,
            const char* plan
    );
    MAKE_CUZMEM_API (
        void cuzmem_set_tuner,
            enum cuzmem_tuner t
    );
#if defined __cplusplus
};
#endif
// -----------------------------------------------

typedef cudaError_t cudaMalloc_cuzmem_t(void**, size_t);
typedef cudaError_t cudaFree_cuzmem_t(void*);

// -- Some fairly nasty Framework Macros ---------
#define CUZMEM_LOAD_SYMBOL(sym, lib)                                   \
    sym##_cuzmem_t *sym = (sym##_cuzmem_t*) dlsym (lib, #sym);          


#define CUZMEM_HOOK                                                    \
    void* libcuzmem = dlopen ("./libcuzmem.so", RTLD_LAZY);            \
    if (!libcuzmem) { printf ("Error Loading libcuzmem\n"); exit(1); } \
    CUZMEM_LOAD_SYMBOL (cudaMalloc, libcuzmem);                        \
    CUZMEM_LOAD_SYMBOL (cudaFree, libcuzmem);                           


#define CUZMEM_INIT                                                    \
    void* libcuzmem = dlopen ("./libcuzmem.so", RTLD_LAZY);            \
    if (!libcuzmem) { printf ("Error Loading libcuzmem\n"); exit(1); } \
    CUZMEM_LOAD_SYMBOL (cuzmem_start, libcuzmem);                      \
    CUZMEM_LOAD_SYMBOL (cuzmem_end, libcuzmem);                        \
    CUZMEM_LOAD_SYMBOL (cuzmem_set_project, libcuzmem);                \
    CUZMEM_LOAD_SYMBOL (cuzmem_set_plan, libcuzmem);                   \
    CUZMEM_LOAD_SYMBOL (cuzmem_set_tuner, libcuzmem);                  \
    CUZMEM_LOAD_SYMBOL (cuzmem_check_plan, libcuzmem);                  


#define CUZMEM_START(mode,gpu_id)   cuzmem_start_label: cuzmem_start(mode,gpu_id) ;


#define CUZMEM_END                             \
    if (CUZMEM_TUNE == cuzmem_end()) {         \
        goto cuzmem_start_label;               \
    }                                           
// -----------------------------------------------

    

#endif // #ifndef _cuzmem_h_
