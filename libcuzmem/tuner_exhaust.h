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

#ifndef _tuner_exhaust_h_
#define _tuner_exhaust_h_

#include "libcuzmem.h"
#include "plans.h"


#if defined __cplusplus
extern "C" {
#endif

cuzmem_plan*
cuzmem_tuner_exhaust (enum cuzmem_tuner_action action, void* parm);

#if defined __cplusplus
};
#endif

#endif
