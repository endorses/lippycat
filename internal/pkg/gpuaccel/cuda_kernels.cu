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
    int* resultCount,
    int maxResults
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
                if (resultIdx < maxResults) {
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
    int* resultCount,
    int maxResults
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

                if (resultIdx < maxResults) {
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

// Dense Aho-Corasick matching kernel. Each thread owns one input and writes to
// its own fixed-size result slice, so no atomics are required. Duplicate
// pattern IDs are suppressed because filter consumers care whether a pattern
// matched, not how many times it occurred in one input.
__global__ void acMatchKernel(
    const char* inputs,
    const int* inputOffsets,
    int numInputs,
    const int* transitions,
    const int* failure,
    const int* outputs,
    const int* outputOffsets,
    const int* patternTypes,
    const int* patternLengths,
    int numStates,
    int* results,
    int* resultCounts,
    int maxMatchesPerInput
) {
    int inputIdx = blockIdx.x * blockDim.x + threadIdx.x;
    if (inputIdx >= numInputs) {
        return;
    }

    int state = 0;
    int resultCount = 0;
    int inputStart = inputOffsets[inputIdx];
    int inputEnd = inputOffsets[inputIdx + 1];
    int resultStart = inputIdx * maxMatchesPerInput;

    for (int pos = inputStart; pos < inputEnd; pos++) {
        unsigned char symbol = static_cast<unsigned char>(inputs[pos]);
        if (symbol >= 'A' && symbol <= 'Z') {
            symbol += 'a' - 'A';
        }
        int nextState = transitions[state * 256 + symbol];

        // Exported dense automatons normally contain resolved transitions for
        // every byte. Follow failure links defensively if an unresolved entry
        // is ever supplied.
        while (nextState < 0 && state != 0) {
            state = failure[state];
            nextState = transitions[state * 256 + symbol];
        }
        state = nextState >= 0 && nextState < numStates ? nextState : 0;

        int outputStart = outputOffsets[state];
        int outputEnd = outputOffsets[state + 1];
        for (int outputIdx = outputStart; outputIdx < outputEnd; outputIdx++) {
            int patternID = outputs[outputIdx];
            int matchEnd = pos - inputStart + 1;
            int matchStart = matchEnd - patternLengths[patternID];
            int inputLength = inputEnd - inputStart;
            // PatternTypeContains=0, Prefix=1, Suffix=2.
            bool valid = patternTypes[patternID] == 0 ||
                (patternTypes[patternID] == 1 && matchStart == 0) ||
                (patternTypes[patternID] == 2 && matchEnd == inputLength);
            if (!valid) {
                continue;
            }
            bool duplicate = false;
            for (int matchIdx = 0; matchIdx < resultCount; matchIdx++) {
                if (results[resultStart + matchIdx] == patternID) {
                    duplicate = true;
                    break;
                }
            }
            if (!duplicate && resultCount < maxMatchesPerInput) {
                results[resultStart + resultCount] = patternID;
                resultCount++;
            }
        }
    }

    resultCounts[inputIdx] = resultCount;
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
    int maxResults,
    cudaStream_t stream
) {
    // Reset result count
    cudaMemsetAsync(d_resultCount, 0, sizeof(int), stream);

    // Launch kernel with optimal block size. Pattern lengths reside in device
    // memory, so selecting the shared-memory variant on the host would require
    // an additional copy. The general kernel supports the complete input.
    int blockSize = 256;
    int numBlocks = (numPackets + blockSize - 1) / blockSize;
    patternMatchKernel<<<numBlocks, blockSize, 0, stream>>>(
        d_packets, d_packetOffsets, numPackets,
        d_patterns, d_patternLengths, numPatterns,
        d_results, d_resultCount, maxResults
    );
}

void launchACMatchKernel(
    const char* d_inputs,
    const int* d_inputOffsets,
    int numInputs,
    const int* d_transitions,
    const int* d_failure,
    const int* d_outputs,
    const int* d_outputOffsets,
    const int* d_patternTypes,
    const int* d_patternLengths,
    int numStates,
    int* d_results,
    int* d_resultCounts,
    int maxMatchesPerInput,
    cudaStream_t stream
) {
    if (numInputs <= 0 || numStates <= 0 || maxMatchesPerInput <= 0) {
        return;
    }

    cudaMemsetAsync(d_resultCounts, 0, numInputs * sizeof(int), stream);

    int blockSize = 256;
    int numBlocks = (numInputs + blockSize - 1) / blockSize;
    acMatchKernel<<<numBlocks, blockSize, 0, stream>>>(
        d_inputs, d_inputOffsets, numInputs,
        d_transitions, d_failure, d_outputs, d_outputOffsets,
        d_patternTypes, d_patternLengths, numStates,
        d_results, d_resultCounts, maxMatchesPerInput
    );
}

}  // extern "C"
