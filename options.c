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
#include <string.h>

#include "fossa.h"
#include "options.h"

void
print_usage (void)
{
    printf (
    "Usage: fossa [options] cuda_program [cuda_program options]\n\n"
    "Options:\n"
    " -m mode      Either \"tune\" or \"run\" (default: run)\n"
    "\n"
    );
    exit (1);
}


void
print_version (void)
{
    printf (
        "fossa  (build " SVN_REV ")\n"
        "Copyright (C) 2011  James A. Shackleford\n\n"

        "fossa is free software: you can redistribute it and/or modify\n"
        "it under the terms of the GNU General Public License as published by\n"
        "the Free Software Foundation, either version 3 of the License, or\n"
        "(at your option) any later version.\n\n"

        "This program is distributed in the hope that it will be useful,\n"
        "but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
        "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
        "GNU General Public License for more details.\n\n"

        "You should have received a copy of the GNU General Public License\n"
        "along with this program.  If not, see <http://www.gnu.org/licenses/>.\n\n"
    );
    exit (1);
}

void
check_syntax (int i, int argc, char* argv[])
{
    if (
        (i == argc-1)          ||
        (argv[i+1][0] == '-')
       )
    {
        fprintf (stderr, "option %s missing argument\n", argv[i]);
        exit (1);
    }
}

void
parse_cmdline (struct fossa_options *opt, int argc, char* argv[])
{
    int i;

    for (i=1; i<argc; i++) {
        // we want to stop at the child program
        if (argv[i][0] != '-') {
            break;
        }

        if (!strcmp (argv[i], "-m")) {
            check_syntax (i++, argc, argv);
            if (!strcmp (argv[i], "tune")) {
                opt->mode = 1;
            }
            else if (!strcmp (argv[i], "run")) {
                opt->mode = 0;
            }
            else {
                fprintf (stderr, "Unknown fossa mode\n");
                print_usage ();
                exit (1);
            }
        }
        else if (!strcmp (argv[i], "--version")) {
            print_version ();
        }
        else {
            print_usage ();
            break;
        }
    }

    if (argc < 2) {
        print_usage ();
    }

    // we have hit the child program argument
    if (argv[i] != NULL) {
        opt->child_prg = argv[i];
        opt->child_argv = &argv[i];
        opt->child_argc = argc - i;
    } else {
        print_usage ();
    }
}
