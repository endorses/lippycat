// CUDA kernels for pattern matching

#include <cuda_runtime.h>
#include <device_launch_parameters.h>

// Simple pattern matching kernel
// Each thread processes one packet against all patterns
__global__ void patternMatchKernel(
    const char* packets,
    const int* packetOffsets,
    int numPackets,
    const char* patterns,
    const int* patternLengths,
    int numPatterns,
    int* results,
    int* resultCount
) {
    int packetIdx = blockIdx.x * blockDim.x + threadIdx.x;

    if (packetIdx >= numPackets) {
        return;
    }

    // Get packet data
    int packetStart = packetOffsets[packetIdx];
    int packetEnd = packetOffsets[packetIdx + 1];
    int packetLen = packetEnd - packetStart;

    // Track pattern offset
    int patternOffset = 0;

    // Search for each pattern
    for (int patternIdx = 0; patternIdx < numPatterns; patternIdx++) {
        int patternLen = patternLengths[patternIdx];

        // Skip if pattern longer than packet
        if (patternLen > packetLen) {
            patternOffset += patternLen;
            continue;
        }

        // Boyer-Moore-Horspool style search
        for (int i = 0; i <= packetLen - patternLen; i++) {
            bool match = true;

            // Check if pattern matches at position i
            for (int j = 0; j < patternLen; j++) {
                if (packets[packetStart + i + j] != patterns[patternOffset + j]) {
                    match = false;
                    break;
                }
            }

            if (match) {
                // Record match atomically
                int resultIdx = atomicAdd(resultCount, 1);

                // Store result: [packetIdx, patternIdx, offset, length]
                if (resultIdx < 10000) {  // Safety limit
                    results[resultIdx * 4 + 0] = packetIdx;
                    results[resultIdx * 4 + 1] = patternIdx;
                    results[resultIdx * 4 + 2] = i;
                    results[resultIdx * 4 + 3] = patternLen;
                }

                break;  // Found match, move to next pattern
            }
        }

        patternOffset += patternLen;
    }
}

// Optimized pattern matching using shared memory
__global__ void patternMatchKernelOptimized(
    const char* packets,
    const int* packetOffsets,
    int numPackets,
    const char* patterns,
    const int* patternLengths,
    int numPatterns,
    int* results,
    int* resultCount
) {
    // Shared memory for pattern data (faster access)
    __shared__ char sharedPatterns[1024];
    __shared__ int sharedLengths[32];

    int packetIdx = blockIdx.x * blockDim.x + threadIdx.x;

    // Cooperatively load patterns into shared memory
    if (threadIdx.x == 0) {
        int totalPatternSize = 0;
        for (int i = 0; i < numPatterns && i < 32; i++) {
            sharedLengths[i] = patternLengths[i];
            totalPatternSize += patternLengths[i];
        }

        if (totalPatternSize < 1024) {
            for (int i = 0; i < totalPatternSize; i++) {
                sharedPatterns[i] = patterns[i];
            }
        }
    }

    __syncthreads();

    if (packetIdx >= numPackets) {
        return;
    }

    // Process packet (similar to basic kernel but using shared memory)
    int packetStart = packetOffsets[packetIdx];
    int packetEnd = packetOffsets[packetIdx + 1];
    int packetLen = packetEnd - packetStart;

    int patternOffset = 0;

    for (int patternIdx = 0; patternIdx < numPatterns && patternIdx < 32; patternIdx++) {
        int patternLen = sharedLengths[patternIdx];

        if (patternLen > packetLen) {
            patternOffset += patternLen;
            continue;
        }

        // Search using shared memory patterns
        for (int i = 0; i <= packetLen - patternLen; i++) {
            bool match = true;

            for (int j = 0; j < patternLen; j++) {
                if (packets[packetStart + i + j] != sharedPatterns[patternOffset + j]) {
                    match = false;
                    break;
                }
            }

            if (match) {
                int resultIdx = atomicAdd(resultCount, 1);

                if (resultIdx < 10000) {
                    results[resultIdx * 4 + 0] = packetIdx;
                    results[resultIdx * 4 + 1] = patternIdx;
                    results[resultIdx * 4 + 2] = i;
                    results[resultIdx * 4 + 3] = patternLen;
                }

                break;
            }
        }

        patternOffset += patternLen;
    }
}

// Call-ID extraction kernel (SIP-specific)
__global__ void extractCallIDKernel(
    const char* packets,
    const int* packetOffsets,
    int numPackets,
    char* callIDs,
    int* callIDOffsets,
    int* callIDCount
) {
    int packetIdx = blockIdx.x * blockDim.x + threadIdx.x;

    if (packetIdx >= numPackets) {
        return;
    }

    int packetStart = packetOffsets[packetIdx];
    int packetEnd = packetOffsets[packetIdx + 1];
    int packetLen = packetEnd - packetStart;

    // Search for "Call-ID:" or "i:"
    const char* callIDHeader = "Call-ID:";
    const char* shortForm = "\ni:";

    int headerLen = 8;
    int foundOffset = -1;

    // Search for Call-ID:
    for (int i = 0; i <= packetLen - headerLen; i++) {
        bool match = true;
        for (int j = 0; j < headerLen; j++) {
            if (packets[packetStart + i + j] != callIDHeader[j]) {
                match = false;
                break;
            }
        }

        if (match) {
            foundOffset = i + headerLen;
            break;
        }
    }

    // If not found, try short form
    if (foundOffset == -1) {
        headerLen = 3;
        for (int i = 0; i <= packetLen - headerLen; i++) {
            bool match = true;
            for (int j = 0; j < headerLen; j++) {
                if (packets[packetStart + i + j] != shortForm[j]) {
                    match = false;
                    break;
                }
            }

            if (match) {
                foundOffset = i + headerLen;
                break;
            }
        }
    }

    if (foundOffset != -1) {
        // Skip whitespace
        while (foundOffset < packetLen &&
               (packets[packetStart + foundOffset] == ' ' ||
                packets[packetStart + foundOffset] == '\t')) {
            foundOffset++;
        }

        // Find end of Call-ID (until \r or \n)
        int callIDStart = foundOffset;
        int callIDEnd = callIDStart;

        while (callIDEnd < packetLen &&
               packets[packetStart + callIDEnd] != '\r' &&
               packets[packetStart + callIDEnd] != '\n') {
            callIDEnd++;
        }

        int callIDLen = callIDEnd - callIDStart;

        if (callIDLen > 0 && callIDLen < 128) {
            // Record Call-ID
            int resultIdx = atomicAdd(callIDCount, 1);

            if (resultIdx < 10000) {
                int outputOffset = resultIdx * 128;
                callIDOffsets[resultIdx] = outputOffset;
                callIDOffsets[resultIdx + 1] = outputOffset + callIDLen;

                // Copy Call-ID
                for (int i = 0; i < callIDLen; i++) {
                    callIDs[outputOffset + i] = packets[packetStart + callIDStart + i];
                }
            }
        }
    }
}

// C wrapper functions for CGo

extern "C" {

void launchPatternMatchKernel(
    const char* d_packets,
    const int* d_packetOffsets,
    int numPackets,
    const char* d_patterns,
    const int* d_patternLengths,
    int numPatterns,
    int* d_results,
    int* d_resultCount,
    cudaStream_t stream
) {
    // Reset result count
    cudaMemsetAsync(d_resultCount, 0, sizeof(int), stream);

    // Launch kernel with optimal block size
    int blockSize = 256;
    int numBlocks = (numPackets + blockSize - 1) / blockSize;

    // Use optimized kernel if patterns fit in shared memory
    bool useOptimized = true;
    int totalPatternSize = 0;
    for (int i = 0; i < numPatterns && i < 32; i++) {
        totalPatternSize += d_patternLengths[i];
    }

    if (totalPatternSize > 1024 || numPatterns > 32) {
        useOptimized = false;
    }

    if (useOptimized) {
        patternMatchKernelOptimized<<<numBlocks, blockSize, 0, stream>>>(
            d_packets, d_packetOffsets, numPackets,
            d_patterns, d_patternLengths, numPatterns,
            d_results, d_resultCount
        );
    } else {
        patternMatchKernel<<<numBlocks, blockSize, 0, stream>>>(
            d_packets, d_packetOffsets, numPackets,
            d_patterns, d_patternLengths, numPatterns,
            d_results, d_resultCount
        );
    }
}

void launchCallIDExtractionKernel(
    const char* d_packets,
    const int* d_packetOffsets,
    int numPackets,
    char* d_callIDs,
    int* d_callIDOffsets,
    int* d_callIDCount,
    cudaStream_t stream
) {
    // Reset result count
    cudaMemsetAsync(d_callIDCount, 0, sizeof(int), stream);

    int blockSize = 256;
    int numBlocks = (numPackets + blockSize - 1) / blockSize;

    extractCallIDKernel<<<numBlocks, blockSize, 0, stream>>>(
        d_packets, d_packetOffsets, numPackets,
        d_callIDs, d_callIDOffsets, d_callIDCount
    );
}

}  // extern "C"