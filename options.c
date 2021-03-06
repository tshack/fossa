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
    " --tune       Generate an optimized memory allocation plan for cuda_program\n"
    " --oom val    Adjust cuda_program's oom_adj value (-17 to +15). [requires sudo]\n"
    "\n"
    " --version    Display version and license information\n"
    " --help       Display this information\n"
    "\n"
    );
    exit (1);
}


void
print_version (void)
{
    printf (
        "fossa " FOSSA_VERSION " (build " SVN_REV ")\n"
        "Copyright (C) 2011  James A. Shackleford\n\n"

        "fossa is free software: you can redistribute it and/or modify\n"
        "it under the terms of the GNU General Public License as published by\n"
        "the Free Software Foundation, either version 3 of the License, or\n"
        "(at your option) any later version.\n\n"

        "This program is distributed in the hope that it will be useful,\n"
        "but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
        "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
        "GNU General Public License for more details.\n\n"
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
        // make sure oparand isn't a negative number
        if ((argv[i+1][1] < 0x30) || (argv[i+1][1] > 0x39)) {
            fprintf (stderr, "option %s missing argument\n", argv[i]);
            exit (1);
        }
    }
}

// we hash opt->child_prg along with its arguments.  we don't want the path
// included in the hash, which would require the same program living in
// different locations (or invoked in differnt ways) to be re-tuned... not
// good.  So we extract the program name here.  the full path is still in
// opt->child_argv[0]
char*
get_child_prg (char* argv0)
{
    if (strrchr (argv0, '/') != NULL) {
        // absolute path to cuda program was used
        return strrchr (argv0, '/') + 1;
    } else {
        // cuda program is in user's path
        return argv0;
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
                fprintf (stderr, "fossa: invalide mode\n");
                print_usage ();
                exit (1);
            }
        }
        else if (!strcmp (argv[i], "--tune")) {
            opt->mode = 1;
        }
        else if (!strcmp (argv[i], "--oom")) {
            check_syntax (i++, argc, argv);
            if ((atoi(argv[i]) < 16) && (atoi(argv[i]) > -18)) {
                opt->oom_adj = atoi(argv[i]);
            }
            else {
                fprintf (stderr, "fossa: invalid oom_adj value\n");
                print_usage ();
                exit (1);
            }
        }
        else if (!strcmp (argv[i], "--version")) {
            print_version ();
        }
        else if (!strcmp (argv[i], "--help")) {
            print_usage ();
        }
        else {
            print_usage ();
            break;
        }
    }

    if (argc < 2) {
        print_usage ();
    }

    // opt->child_prg is just the program name
    // the full path lives in opt->argv[0]

    // we have hit the child program argument
    if (argv[i] != NULL) {
        opt->child_prg = get_child_prg (argv[i]);
        opt->child_argv = &argv[i];
        opt->child_argc = argc - i;
    } else {
        print_usage ();
    }
}

