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
#include <gcrypt.h>

#include "fossa.h"
#include "options.h"
#include "hash.h"


// SHA-256 is pretty collision resistant... right?
char*
hash (struct fossa_options *opt)
{
    int i;
    unsigned char *hash;
    char *out, *p;
    char input[259];
    int input_len;
    int hash_len;

    strcpy (input, "");
    strcat (input, opt->child_prg);
    for (i=1; i<opt->child_argc; i++) {
        strcat (input, opt->child_argv[i]);
        strcat (input, " ");
    }

    // Length of message to hash
    input_len = strlen (input);

    // Length of sha-256 hash
    hash_len = gcry_md_get_algo_dlen (GCRY_MD_SHA256);

    // output sha1 hash - this will be binary data
    hash = (unsigned char*)malloc (sizeof (unsigned char) * hash_len);

    // output sha1 hash - converted to hex representation
    // 2 hex digits for every byte + 1 for trailing \0
    out = (char*)malloc (sizeof(char) * ((2*hash_len) + 1));
    p = out;

    // compute the SHA1 digest
    gcry_md_hash_buffer (GCRY_MD_SHA256, hash, input, input_len);

    // Convert each byte to its 2 digit ascii
    // hex representation and place in out
    for (i=0; i<hash_len; i++, p += 2 ) {
        snprintf (p, 3, "%02x", hash[i]);
    }
    free (hash);

    return out;
}

