#include <stdlib.h>
#include <stdio.h>
#include <cuda.h>

#define GPU_MEM_MAX 4000000000


int
main (int argc, char* argv[])
{
    size_t new_size;
    size_t free;
    size_t total;
    size_t alloc_size;
    char* gpu_mem;


    if (argc < 2) {
       fprintf (stderr, "Please specify desired size of GPU memory\n\n"); 
       return 0;
    }
    new_size = atoi (argv[1]);

    cudaMemGetInfo (&free, &total);
    free /= 1000000;
    total /= 1000000;

    printf ("GPU Memory: %i/%i MB available\n\n", free, total);

    if (free < new_size) {
        fprintf (stderr, "GPU is already smaller than %i MB\n", new_size);
        exit (0);
    }

    printf ("Shrinking GPU Memory... ");
    fflush (stdout);

    alloc_size = (free - new_size) * sizeof (char) * 1000000;
    cudaMalloc ((void**) &gpu_mem, alloc_size);

    printf ("done.\n\n");

    cudaMemGetInfo (&free, &total);

    printf ("GPU Memory: %i/%i MB available\n\n", free/1000000, total/1000000);

    printf ("Ctrl-C to exit...\n");

    while (1);
}

