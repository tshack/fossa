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

#ifndef _tuner_util_h_
#define _tuner_util_h_

#include "plans.h"


#if defined __cplusplus
extern "C" {
#endif

unsigned int
num_bits (unsigned long long n);

unsigned int
detect_inloop (cuzmem_plan** entry, size_t size);

unsigned int
check_inloop (cuzmem_plan** entry, size_t size);

// standard tuner handlers
cuzmem_plan*
zeroth_lookup_handler (CUZMEM_CONTEXT ctx, size_t size);

unsigned int
zeroth_end_handler (CUZMEM_CONTEXT ctx);

unsigned int
loopy_entry (CUZMEM_CONTEXT ctx, cuzmem_plan** entry, size_t size);

cuzmem_plan*
loopy_entry_handler (cuzmem_plan* entry, size_t size);

const char*
binary (unsigned long long x);

#if defined __cplusplus
};
#endif

#endif
