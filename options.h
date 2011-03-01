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

#ifndef _options_h_
#define _options_h_

#include "fossa.h"

struct fossa_options {
    unsigned int mode;
    unsigned int tuner;
    char* child_prg;
    char** child_argv;
    int child_argc;
    int oom_adj;
};

void
parse_cmdline (struct fossa_options *opt, int argc, char* argv[]);

#endif /* #ifndef _options_h_ */
