// +build ignore

package main

/*
#cgo CFLAGS: -I/opt/cuda/include
#cgo LDFLAGS: -L/opt/cuda/lib64 -lcudart

#include <cuda_runtime.h>
#include <stdio.h>

int testCUDA() {
    int deviceCount = 0;
    cudaError_t err = cudaGetDeviceCount(&deviceCount);

    if (err != cudaSuccess) {
        printf("CUDA Error: %s\n", cudaGetErrorString(err));
        return -1;
    }

    printf("Found %d CUDA device(s)\n", deviceCount);

    if (deviceCount > 0) {
        struct cudaDeviceProp prop;
        cudaGetDeviceProperties(&prop, 0);
        printf("Device 0: %s\n", prop.name);
        printf("Compute Capability: %d.%d\n", prop.major, prop.minor);
        printf("Total Memory: %zu MB\n", prop.totalGlobalMem / (1024*1024));
    }

    return deviceCount;
}
*/
import "C"
import "fmt"

func main() {
	fmt.Println("Testing CUDA availability...")
	count := C.testCUDA()
	if count >= 0 {
		fmt.Printf("Success! CUDA is working with %d device(s)\n", count)
	} else {
		fmt.Println("CUDA test failed")
	}
}