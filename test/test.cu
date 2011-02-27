#include <stdlib.h>
#include <stdio.h>
#include <cuda.h>

#define BLOCK_SIZE 50
#define GPU_MEM_MAX 4000000000

// allocate cpu memory and initialite element i to contain the value i
float*
init_cpu_mem (int block_size)
{
    int i;
    float *cpu_mem;
    size_t block_size_t;

    // convert from MB to bytes
    block_size_t = block_size * 250000 * sizeof (float);

    fprintf (stderr, "Initializing a %iMB block of CPU memory... ", block_size);
    cpu_mem = (float*)malloc (block_size_t);

    for (i=0; i<block_size; i++) {
        cpu_mem[i] = (float)i;
    }
    fprintf (stderr, "done.\n\n");

    return cpu_mem;
}


// allocate num_blocks of block_size (MB) GPU memory
float**
init_gpu_mem (int num_blocks, int block_size)
{
    int i;
    float **gpu_mem;

    fprintf (stderr, "Allocating %i %iMB blocks of GPU memory.\n", num_blocks, block_size);

    // convert from MB to bytes
    block_size *= 250000 * sizeof (float);

    gpu_mem = (float**)malloc (sizeof(float*) * num_blocks);

    for (i=0; i<num_blocks; i++) {
        fprintf (stderr, "  Block %02i... ", i);
        cudaMalloc ((void **)&gpu_mem[i], block_size);
        if (gpu_mem[i] == NULL) {
            fprintf (stderr, "out of memory.\n");
            fprintf (stderr, "Exiting...\n\n");
            exit (0);
        } else {
            fprintf (stderr, "done.\n");
        }
    }

    return gpu_mem;
}


// free all GPU memory blocks
void
free_gpu_mem (float** gpu_mem, int num_blocks)
{
    int i;

    for (i=0; i<num_blocks; i++) {
        cudaFree (gpu_mem[i]);
    }

    free (gpu_mem);
}


// GPU address bus is 32-bit... we can't address more than 4GB
int
sanity_check (int num_blocks, int block_size)
{
    size_t block_size_t;

    block_size_t = block_size * 250000 * sizeof (float);

    if (block_size_t*num_blocks > GPU_MEM_MAX) {
        fprintf (stderr, "Cannot allocate %i %iMB blocks (%1.2fGB).  GPU memory map is limited to %iGB\n",
                num_blocks, block_size, (num_blocks*block_size)/1000.f, GPU_MEM_MAX/1000000000);
        return -1;
    } else {
        return 0;
    }
}


// ripple copy the contents of the CPU memory block through the
// GPU blocks.  check the contents of the final GPU block against the
// CPU block... it's a game of telephone.
int
mem_test (float** gpu_mem, float* cpu_mem, int num_blocks, int block_size)
{
    int i;
    size_t block_size_t;
    float *gpu_tmp;

    block_size_t = block_size * 250000 * sizeof (float);

    fprintf (stderr, "Performing memory test... ");

    // 1st copy CPU block to GPU block 0
    cudaMemcpy (gpu_mem[0], cpu_mem, block_size_t, cudaMemcpyHostToDevice);

    // now ripple the CPU block information through the GPU memory blocks
    for (i=1; i<num_blocks; i++) {
        cudaMemcpy (gpu_mem[i], gpu_mem[i-1], block_size_t, cudaMemcpyDeviceToDevice);
    }

    gpu_tmp = (float*)malloc (block_size_t);

    cudaMemcpy (gpu_tmp, gpu_mem[num_blocks-1], block_size_t, cudaMemcpyDeviceToHost);

    // now compare the CPU block to the last GPU block
    for (i=0; i<block_size; i++) {
        if (gpu_tmp[i] != cpu_mem[i]) {
            fprintf (stderr, "FAILED\n\n");
            free (gpu_tmp);
            return -1;
        }
    }
    fprintf (stderr, "PASSED\n\n");
    free (gpu_tmp);

    return 0;
}


int
main (int argc, char* argv[])
{
    int i;
    int num_blocks;
    int result;
    float  *cpu_mem;
    float **gpu_mem;

    if (argc < 2) {
       fprintf (stderr, "Please specify # of 50MB Blocks to allocate\n\n"); 
       return 0;
    }
    num_blocks = atoi (argv[1]);

    if (sanity_check (num_blocks, BLOCK_SIZE) == -1) {
        return 0;
    }

    cpu_mem = init_cpu_mem (BLOCK_SIZE);
    gpu_mem = init_gpu_mem (num_blocks, BLOCK_SIZE);
   

    mem_test (gpu_mem, cpu_mem, num_blocks, BLOCK_SIZE);


    free_gpu_mem (gpu_mem, num_blocks);

    return 0;
}

