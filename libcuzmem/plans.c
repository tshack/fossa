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
#include <ctype.h>
#include <sys/stat.h>
#include <string.h>

#include "libcuzmem.h"
#include "plans.h"

size_t
rm_whitespace (char *str)
{
    char *dst = str;
    char *src = str;
    char c;
    while ((c = *src++) != '\0') {
        if (isspace (c)) {
            if (src-1 != str) {
                *dst++ = ' ';
            }
            while ((c = *src++) != '\0' && isspace (c)) {
                ;
            }
            if (c == '\0') {
                break;
            }
        }
        *dst++ = c;
    }
    *dst = '\0';
    return (dst - str);
}


void
plan_add_entry (
    cuzmem_plan** plan,
    char** cmd,
    char** parm,
    char* linebuf,
    FILE* fp
)
{
    int line_len = 0;
    cuzmem_plan* entry = (cuzmem_plan*) malloc (sizeof(cuzmem_plan));

    // populate entry with default values
    entry->id = 0;
    entry->size = 0;
    entry->loc = 1;
    entry->inloop = 0;
    entry->cpu_pointer = NULL;
    entry->gpu_pointer = NULL;

    while (fgets (linebuf, 128, fp)) {
        // Comments start with # (skip to next line)
        if (linebuf[0] == '#') {
            continue;
        }

        // Remove excess whitespace
        line_len = rm_whitespace (linebuf);

        // Skip empty lines
        if (line_len == 0) {
            continue;
        }

        *cmd  = (char*) realloc (*cmd, line_len * sizeof(char));
        *parm = (char*) realloc (*parm, line_len * sizeof(char));

        // Get the command/parameter set
        sscanf (linebuf, "%s %s", *cmd, *parm);

        // Populate plan entry
        if (!strcmp (*cmd, "id")) {
            entry->id = atoi(*parm);
        }
        else if (!strcmp (*cmd, "size")) {
            entry->size = atoi(*parm);
        }
        else if (!strcmp (*cmd, "loc")) {
            if (!strcmp (*parm, "global")) {
                entry->loc = 1;
            }
            else if (!strcmp (*parm, "pinned")) {
                entry->loc = 0;
            }
            else {
                fprintf (stderr, "libcuzmem: bad memory location specified.\n");
                exit (1);
            }
        }
        else if (!strcmp (*cmd, "inloop")) {
            if (!strcmp (*parm, "true")) {
                entry->inloop = 1;
            }
            else if (!strcmp (*parm, "false")) {
                entry->inloop = 0;
            }
            else {
                fprintf (stderr, "libcuzmem: bad inloop specification.\n");
                exit (1);
            }
        }
        else if (!strcmp (*cmd, "end")) {
            break;
        }
        else {
            // Unknown (just ignore)
            ;
        }
    } // while

    // Insert new entry into plan
    entry->next = *plan;
    *plan = entry;
}


// Reads specified file and returns
cuzmem_plan*
read_plan (char *project_name, char *plan_name)
{
    // TODO: Check valid project_name & plan_name before reading
    //
    FILE *fp;
    char filename[FILENAME_MAX];
    char linebuf[128];
    char *cmd, *parm, *home;
    unsigned int flen;
    unsigned int line_number;
    int line_len;
    cuzmem_plan *plan = NULL;

    sprintf (filename, "%s/.%s/%s.plan", getenv ("HOME"), project_name, plan_name);

    // open the file
    fp = fopen (filename, "r");
    if (!fp) {
        fprintf (stderr, "libcuzmem: unable to open plan %s\n\n", filename);
        exit (0);
    }

    // Do dummy malloc()s
    cmd  = (char*) malloc (1*sizeof(char));
    parm = (char*) malloc (1*sizeof(char));

    while (fgets (linebuf, 128, fp)) {
        // Comments start with # (skip to next line)
        if (linebuf[0] == '#') {
            continue;
        }

        // Remove excess whitespace
        line_len = rm_whitespace (linebuf);

        // Skip empty lines
        if (line_len == 0) {
            continue;
        }

        cmd  = (char*) realloc (cmd, line_len * sizeof(char));
        parm = (char*) realloc (parm, line_len * sizeof(char));

        // Get the command/parameter set
        sscanf (linebuf, "%s %s", cmd, parm);

        if (!strcmp (cmd, "begin")) {
            plan_add_entry (&plan, &cmd, &parm, linebuf, fp);
        }
    }

    free (cmd);
    free (parm);

    fclose (fp);

    return plan;
}



void
write_plan (cuzmem_plan* plan, char *project_name, char *plan_name)
{
    FILE *fp;
    char *home;
    char filename[FILENAME_MAX];
    unsigned int i;

    struct stat st;

    unsigned int num_entries = 0;
    cuzmem_plan* curr = plan;

    strcpy (filename, "");

    home = getenv ("HOME");
    strcat (filename, home);
    strcat (filename, "/.");
    strcat (filename, project_name);

    // .project does not exist (create it)
    if (stat (filename, &st) != 0) {
        if (mkdir (filename, 0755)) {
            fprintf (stderr, "libcuzmem: could not create project directory!\n");
            fprintf (stderr, "  (%s)\n", filename);
            exit (1);
        }
    }

    strcat (filename, "/");
    strcat (filename, plan_name);
    strcat (filename, ".plan");

    fp = fopen (filename, "w");
    if (!fp) {
        fprintf (stderr, "libcuzmem: unable to open plan %s\n\n", filename);
        exit (0);
    }

    // Get # of entries
    while (curr != NULL) {
        num_entries++;
        curr = curr->next;
    }

    // Write entries to plan file in order
    fprintf (fp, "# libcuzmem plan file\n\n");
    for (i=0; i<num_entries; i++) {
        curr = plan;
        while (curr != NULL) {
            if (curr->id == i) {
                fprintf (fp, "begin\n");
                fprintf (fp, "  id %i\n", curr->id);
                fprintf (fp, "  size %i\n", (int)curr->size);
                if (curr->loc == 0) {
                    fprintf (fp, "  loc pinned\n");
                }
                else if (curr->loc == 1) {
                    fprintf (fp, "  loc global\n");
                }
                else {
                    fprintf (stderr, "libcuzmem: attempted to write invalid memory spec to plan!\n");
                    exit (1);
                }
                if (curr->inloop == 1) {
                    fprintf (fp, "  inloop true\n");
                }
                fprintf (fp, "end\n\n");
                break;
            }
            curr = curr->next;
        }
    }

    fclose (fp);
}

int
check_plan (const char* project_name, const char* plan_name)
{
    struct stat st;
    char filename[FILENAME_MAX];

    sprintf (filename, "%s/.%s/%s.plan", getenv ("HOME"), project_name, plan_name);

    if (stat (filename, &st) != 0) {
        // plan does not exist
        return 1;
    } else {
        // plan does exist
        return 0;
    }
}
