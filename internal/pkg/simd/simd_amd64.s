// +build amd64,!cuda

#include "textflag.h"

// func bytesEqualAVX2(a, b []byte) bool
TEXT ·bytesEqualAVX2(SB), NOSPLIT, $0-49
    MOVQ a_base+0(FP), SI    // SI = &a[0]
    MOVQ b_base+24(FP), DI   // DI = &b[0]
    MOVQ a_len+8(FP), CX     // CX = len(a)
    XORQ AX, AX              // AX = 0 (false)

    // Already checked len(a) == len(b) in Go code
    CMPQ CX, $32
    JB scalar_equal

avx2_loop:
    CMPQ CX, $32
    JB tail_equal

    // Load 32 bytes from both arrays
    VMOVDQU (SI), Y0
    VMOVDQU (DI), Y1

    // Compare for equality
    VPCMPEQB Y0, Y1, Y2

    // Check if all bytes are equal
    VPMOVMSKB Y2, AX
    CMPL AX, $0xFFFFFFFF
    JNE not_equal

    // Advance pointers
    ADDQ $32, SI
    ADDQ $32, DI
    SUBQ $32, CX
    JMP avx2_loop

tail_equal:
    CMPQ CX, $0
    JE equal

    // Process remaining bytes with scalar
scalar_equal:
    CMPQ CX, $0
    JE equal

    MOVB (SI), AX
    CMPB AX, (DI)
    JNE not_equal

    INCQ SI
    INCQ DI
    DECQ CX
    JMP scalar_equal

equal:
    MOVB $1, ret+48(FP)
    VZEROUPPER
    RET

not_equal:
    MOVB $0, ret+48(FP)
    VZEROUPPER
    RET

// func bytesEqualSSE2(a, b []byte) bool
TEXT ·bytesEqualSSE2(SB), NOSPLIT, $0-49
    MOVQ a_base+0(FP), SI    // SI = &a[0]
    MOVQ b_base+24(FP), DI   // DI = &b[0]
    MOVQ a_len+8(FP), CX     // CX = len(a)
    XORQ AX, AX              // AX = 0

    CMPQ CX, $16
    JB scalar_equal_sse2

sse2_loop:
    CMPQ CX, $16
    JB tail_equal_sse2

    // Load 16 bytes from both arrays
    MOVOU (SI), X0
    MOVOU (DI), X1

    // Compare for equality
    PCMPEQB X1, X0

    // Check if all bytes are equal
    PMOVMSKB X0, AX
    CMPL AX, $0xFFFF
    JNE not_equal_sse2

    // Advance pointers
    ADDQ $16, SI
    ADDQ $16, DI
    SUBQ $16, CX
    JMP sse2_loop

tail_equal_sse2:
    CMPQ CX, $0
    JE equal_sse2

scalar_equal_sse2:
    CMPQ CX, $0
    JE equal_sse2

    MOVB (SI), AX
    CMPB AX, (DI)
    JNE not_equal_sse2

    INCQ SI
    INCQ DI
    DECQ CX
    JMP scalar_equal_sse2

equal_sse2:
    MOVB $1, ret+48(FP)
    RET

not_equal_sse2:
    MOVB $0, ret+48(FP)
    RET

// func indexByteAVX2(s []byte, c byte) int
TEXT ·indexByteAVX2(SB), NOSPLIT, $0-40
    MOVQ s_base+0(FP), SI     // SI = &s[0]
    MOVQ s_len+8(FP), CX      // CX = len(s)
    MOVBQZX c+24(FP), DX      // DX = c (zero-extended)

    // Broadcast byte to all positions in YMM register
    MOVD DX, X0
    VPBROADCASTB X0, Y0

    XORQ AX, AX               // AX = current index

avx2_search_loop:
    CMPQ CX, $32
    JB tail_search_avx2

    // Load 32 bytes
    VMOVDQU (SI), Y1

    // Compare with target byte
    VPCMPEQB Y0, Y1, Y2

    // Get mask of matches
    VPMOVMSKB Y2, DX
    TESTL DX, DX
    JNZ found_avx2

    // Advance
    ADDQ $32, SI
    ADDQ $32, AX
    SUBQ $32, CX
    JMP avx2_search_loop

tail_search_avx2:
    VZEROUPPER

    // Scalar search for remaining bytes
    CMPQ CX, $0
    JE not_found_avx2

scalar_search_avx2:
    MOVB (SI), DX
    CMPB DL, c+24(FP)
    JE found_scalar_avx2

    INCQ SI
    INCQ AX
    DECQ CX
    CMPQ CX, $0
    JNE scalar_search_avx2

not_found_avx2:
    MOVQ $-1, ret+32(FP)
    RET

found_avx2:
    // Find first set bit in mask
    BSFL DX, DX
    ADDQ DX, AX
    MOVQ AX, ret+32(FP)
    VZEROUPPER
    RET

found_scalar_avx2:
    MOVQ AX, ret+32(FP)
    RET

// func indexByteSSE2(s []byte, c byte) int
TEXT ·indexByteSSE2(SB), NOSPLIT, $0-40
    MOVQ s_base+0(FP), SI     // SI = &s[0]
    MOVQ s_len+8(FP), CX      // CX = len(s)
    MOVBQZX c+24(FP), DX      // DX = c

    // Broadcast byte to all positions
    MOVD DX, X0
    PUNPCKLBW X0, X0
    PUNPCKLWL X0, X0
    PSHUFD $0, X0, X0

    XORQ AX, AX

sse2_search_loop:
    CMPQ CX, $16
    JB tail_search_sse2

    // Load 16 bytes
    MOVOU (SI), X1

    // Compare
    PCMPEQB X0, X1

    // Get mask
    PMOVMSKB X1, DX
    TESTL DX, DX
    JNZ found_sse2

    // Advance
    ADDQ $16, SI
    ADDQ $16, AX
    SUBQ $16, CX
    JMP sse2_search_loop

tail_search_sse2:
    CMPQ CX, $0
    JE not_found_sse2

scalar_search_sse2:
    MOVB (SI), DX
    CMPB DL, c+24(FP)
    JE found_scalar_sse2

    INCQ SI
    INCQ AX
    DECQ CX
    CMPQ CX, $0
    JNE scalar_search_sse2

not_found_sse2:
    MOVQ $-1, ret+32(FP)
    RET

found_sse2:
    BSFL DX, DX
    ADDQ DX, AX
    MOVQ AX, ret+32(FP)
    RET

found_scalar_sse2:
    MOVQ AX, ret+32(FP)
    RET
