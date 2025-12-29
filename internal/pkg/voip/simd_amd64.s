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

// func indexByteAVX2(data []byte, c byte) int
TEXT ·indexByteAVX2(SB), NOSPLIT, $0-40
    MOVQ data_base+0(FP), SI  // SI = &data[0]
    MOVQ data_len+8(FP), CX   // CX = len(data)
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

// func indexByteSSE2(data []byte, c byte) int
TEXT ·indexByteSSE2(SB), NOSPLIT, $0-40
    MOVQ data_base+0(FP), SI  // SI = &data[0]
    MOVQ data_len+8(FP), CX   // CX = len(data)
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

// SIP method strings for PCMPESTRI matching
// Methods are ordered by frequency for early exit optimization
DATA sipMethodINVITE<>+0(SB)/8, $"INVITE \x00"
GLOBL sipMethodINVITE<>(SB), RODATA, $8

DATA sipMethodREGISTER<>+0(SB)/8, $"REGISTER"
GLOBL sipMethodREGISTER<>(SB), RODATA, $8

DATA sipMethodBYE<>+0(SB)/8, $"BYE \x00\x00\x00\x00"
GLOBL sipMethodBYE<>(SB), RODATA, $8

DATA sipMethodCANCEL<>+0(SB)/8, $"CANCEL \x00"
GLOBL sipMethodCANCEL<>(SB), RODATA, $8

DATA sipMethodACK<>+0(SB)/8, $"ACK \x00\x00\x00\x00"
GLOBL sipMethodACK<>(SB), RODATA, $8

DATA sipMethodOPTIONS<>+0(SB)/8, $"OPTIONS "
GLOBL sipMethodOPTIONS<>(SB), RODATA, $8

DATA sipMethodSIP<>+0(SB)/8, $"SIP/2.0 "
GLOBL sipMethodSIP<>(SB), RODATA, $8

// func sipMethodMatchSSE42Asm(line []byte) int
// Returns: 1=INVITE, 2=REGISTER, 3=BYE, 4=CANCEL, 5=ACK, 6=OPTIONS, -1=SIP/2.0, 0=no match
TEXT ·sipMethodMatchSSE42Asm(SB), NOSPLIT, $0-32
    MOVQ line_base+0(FP), SI    // SI = &line[0]
    MOVQ line_len+8(FP), CX     // CX = len(line)

    // Check minimum length (3 for BYE/ACK)
    CMPQ CX, $3
    JL no_match

    // Load first byte for fast dispatch
    MOVB (SI), AL

    // Fast dispatch based on first character
    CMPB AL, $'I'
    JE check_invite
    CMPB AL, $'R'
    JE check_register
    CMPB AL, $'B'
    JE check_bye
    CMPB AL, $'C'
    JE check_cancel
    CMPB AL, $'A'
    JE check_ack
    CMPB AL, $'O'
    JE check_options
    CMPB AL, $'S'
    JE check_sip
    JMP no_match

check_invite:
    CMPQ CX, $6
    JL no_match
    // Load 8 bytes from line (we know len >= 6)
    MOVQ (SI), AX
    // Compare first 6 bytes with "INVITE"
    MOVQ sipMethodINVITE<>(SB), DX
    // Mask to compare only 6 bytes: 0x0000FFFFFFFFFFFF
    MOVQ $0x0000FFFFFFFFFFFF, R8
    ANDQ R8, AX
    ANDQ R8, DX
    CMPQ AX, DX
    JE match_invite
    JMP no_match

check_register:
    CMPQ CX, $8
    JL no_match
    MOVQ (SI), AX
    MOVQ sipMethodREGISTER<>(SB), DX
    CMPQ AX, DX
    JE match_register
    JMP no_match

check_bye:
    CMPQ CX, $3
    JL no_match
    // Load 4 bytes, mask to 3
    MOVL (SI), AX
    MOVL sipMethodBYE<>(SB), DX
    ANDL $0x00FFFFFF, AX
    ANDL $0x00FFFFFF, DX
    CMPL AX, DX
    JE match_bye
    JMP no_match

check_cancel:
    CMPQ CX, $6
    JL no_match
    MOVQ (SI), AX
    MOVQ sipMethodCANCEL<>(SB), DX
    MOVQ $0x0000FFFFFFFFFFFF, R8
    ANDQ R8, AX
    ANDQ R8, DX
    CMPQ AX, DX
    JE match_cancel
    JMP no_match

check_ack:
    CMPQ CX, $3
    JL no_match
    MOVL (SI), AX
    MOVL sipMethodACK<>(SB), DX
    ANDL $0x00FFFFFF, AX
    ANDL $0x00FFFFFF, DX
    CMPL AX, DX
    JE match_ack
    JMP no_match

check_options:
    CMPQ CX, $7
    JL no_match
    MOVQ (SI), AX
    MOVQ sipMethodOPTIONS<>(SB), DX
    // Mask for 7 bytes: 0x00FFFFFFFFFFFFFF
    MOVQ $0x00FFFFFFFFFFFFFF, R8
    ANDQ R8, AX
    ANDQ R8, DX
    CMPQ AX, DX
    JE match_options
    JMP no_match

check_sip:
    CMPQ CX, $7
    JL no_match
    MOVQ (SI), AX
    MOVQ sipMethodSIP<>(SB), DX
    MOVQ $0x00FFFFFFFFFFFFFF, R8
    ANDQ R8, AX
    ANDQ R8, DX
    CMPQ AX, DX
    JE match_sip
    JMP no_match

match_invite:
    MOVQ $1, ret+24(FP)
    RET

match_register:
    MOVQ $2, ret+24(FP)
    RET

match_bye:
    MOVQ $3, ret+24(FP)
    RET

match_cancel:
    MOVQ $4, ret+24(FP)
    RET

match_ack:
    MOVQ $5, ret+24(FP)
    RET

match_options:
    MOVQ $6, ret+24(FP)
    RET

match_sip:
    MOVQ $-1, ret+24(FP)
    RET

no_match:
    MOVQ $0, ret+24(FP)
    RET
