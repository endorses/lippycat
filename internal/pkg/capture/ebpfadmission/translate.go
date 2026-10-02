package ebpfadmission

import (
	"fmt"
	"github.com/cilium/ebpf/asm"
	"golang.org/x/net/bpf"
)

// Translate composes libpcap's predicate with the embedded socket policy. Unlike
// cbpfc, this uses socket-context packet loads: SOCKET_FILTER cannot access
// __sk_buff.data/data_end. Unsupported ancillary extensions fail before attach.
// R6 retains skb; R7/R8 implement classic A/X; classic scratch lives at -4..-64
// and is dead before the C program begins. Packet loads reject out-of-bounds in
// the kernel, exactly as classic socket filters do.
func Translate(raw []bpf.RawInstruction) (asm.Instructions, error) {
	return translate(raw, 0)
}

func translate(raw []bpf.RawInstruction, domain uint32) (asm.Instructions, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	decoded, ok := bpf.Disassemble(raw)
	if !ok {
		return nil, fmt.Errorf("invalid classic BPF instruction")
	}
	// Validate forward branches, initialized scratch, divisors and final return.
	if _, err := bpf.NewVM(decoded); err != nil {
		return nil, fmt.Errorf("invalid classic BPF: %w", err)
	}
	label := func(i int) string { return fmt.Sprintf("capture_%d", i) }
	out := asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1), asm.Mov.Imm(asm.R7, 0), asm.Mov.Imm(asm.R8, 0)}
	reg := func(r bpf.Register) asm.Register {
		if r == bpf.RegX {
			return asm.R8
		}
		return asm.R7
	}
	size := func(n int) asm.Size {
		switch n {
		case 1:
			return asm.Byte
		case 2:
			return asm.Half
		default:
			return asm.Word
		}
	}
	alu := map[bpf.ALUOp]asm.ALUOp{bpf.ALUOpAdd: asm.Add, bpf.ALUOpSub: asm.Sub, bpf.ALUOpMul: asm.Mul, bpf.ALUOpDiv: asm.Div, bpf.ALUOpOr: asm.Or, bpf.ALUOpAnd: asm.And, bpf.ALUOpShiftLeft: asm.LSh, bpf.ALUOpShiftRight: asm.RSh, bpf.ALUOpMod: asm.Mod, bpf.ALUOpXor: asm.Xor}
	jumps := map[bpf.JumpTest]asm.JumpOp{bpf.JumpEqual: asm.JEq, bpf.JumpNotEqual: asm.JNE, bpf.JumpGreaterThan: asm.JGT, bpf.JumpLessThan: asm.JLT, bpf.JumpGreaterOrEqual: asm.JGE, bpf.JumpLessOrEqual: asm.JLE, bpf.JumpBitsSet: asm.JSet}
	for i, ins := range decoded {
		var code asm.Instructions
		switch v := ins.(type) {
		case bpf.LoadConstant:
			code = append(code, asm.Mov.Imm32(reg(v.Dst), int32(v.Val)))
		case bpf.LoadScratch:
			code = append(code, asm.LoadMem(reg(v.Dst), asm.R10, int16(-4*(v.N+1)), asm.Word))
		case bpf.StoreScratch:
			code = append(code, asm.StoreMem(asm.R10, int16(-4*(v.N+1)), reg(v.Src), asm.Word))
		case bpf.LoadAbsolute:
			if int32(v.Off) < 0 {
				return nil, fmt.Errorf("unsupported socket ancillary offset %#x", v.Off)
			}
			code = append(code, asm.LoadAbs(int32(v.Off), size(v.Size)), asm.Mov.Reg32(asm.R7, asm.R0))
		case bpf.LoadIndirect:
			if int32(v.Off) < 0 {
				return nil, fmt.Errorf("unsupported indirect offset %#x", v.Off)
			}
			code = append(code, asm.LoadInd(asm.R0, asm.R8, int32(v.Off), size(v.Size)), asm.Mov.Reg32(asm.R7, asm.R0))
		case bpf.LoadMemShift:
			if int32(v.Off) < 0 {
				return nil, fmt.Errorf("unsupported memshift offset")
			}
			code = append(code, asm.LoadAbs(int32(v.Off), asm.Byte), asm.And.Imm32(asm.R0, 15), asm.LSh.Imm32(asm.R0, 2), asm.Mov.Reg32(asm.R8, asm.R0))
		case bpf.LoadExtension:
			if v.Num != bpf.ExtLen {
				return nil, fmt.Errorf("unsupported classic extension %d", v.Num)
			}
			code = append(code, asm.LoadMem(asm.R7, asm.R6, 0, asm.Word))
		case bpf.ALUOpConstant:
			op, ok := alu[v.Op]
			if !ok {
				return nil, fmt.Errorf("unsupported classic ALU %d", v.Op)
			}
			code = append(code, op.Imm32(asm.R7, int32(v.Val)))
		case bpf.ALUOpX:
			op, ok := alu[v.Op]
			if !ok {
				return nil, fmt.Errorf("unsupported classic ALU %d", v.Op)
			}
			if v.Op == bpf.ALUOpDiv || v.Op == bpf.ALUOpMod {
				code = append(code, asm.JEq.Imm(asm.R8, 0, "capture_reject"))
			}
			code = append(code, op.Reg32(asm.R7, asm.R8))
		case bpf.NegateA:
			code = append(code, asm.Neg.Imm32(asm.R7, 0))
		case bpf.TXA:
			code = append(code, asm.Mov.Reg32(asm.R7, asm.R8))
		case bpf.TAX:
			code = append(code, asm.Mov.Reg32(asm.R8, asm.R7))
		case bpf.Jump:
			code = append(code, asm.Ja.Label(label(i+1+int(v.Skip))))
		case bpf.JumpIf:
			jt, jf := label(i+1+int(v.SkipTrue)), label(i+1+int(v.SkipFalse))
			cond := v.Cond
			if cond == bpf.JumpBitsNotSet {
				cond = bpf.JumpBitsSet
				jt, jf = jf, jt
			}
			op, ok := jumps[cond]
			if !ok {
				return nil, fmt.Errorf("unsupported jump %d", v.Cond)
			}
			code = append(code, asm.Mov.Imm32(asm.R9, int32(v.Val)), op.Reg(asm.R7, asm.R9, jt), asm.Ja.Label(jf))
		case bpf.JumpIfX:
			jt, jf := label(i+1+int(v.SkipTrue)), label(i+1+int(v.SkipFalse))
			cond := v.Cond
			if cond == bpf.JumpBitsNotSet {
				cond = bpf.JumpBitsSet
				jt, jf = jf, jt
			}
			op, ok := jumps[cond]
			if !ok {
				return nil, fmt.Errorf("unsupported jump %d", v.Cond)
			}
			code = append(code, op.Reg(asm.R7, asm.R8, jt), asm.Ja.Label(jf))
		case bpf.RetConstant:
			target := "capture_accept"
			if v.Val == 0 {
				target = "capture_reject"
			}
			code = append(code, asm.Ja.Label(target))
		case bpf.RetA:
			code = append(code, asm.JEq.Imm(asm.R7, 0, "capture_reject"), asm.Ja.Label("capture_accept"))
		default:
			return nil, fmt.Errorf("unsupported classic instruction %T", ins)
		}
		code[0] = code[0].WithSymbol(label(i))
		out = append(out, code...)
	}
	out = append(out,
		asm.StoreImm(asm.R10, -68, int64(domain*16+12), asm.Word).WithSymbol("capture_reject"),
		asm.LoadMapPtr(asm.R1, 0).WithReference("counters"),
		asm.Mov.Reg(asm.R2, asm.R10), asm.Add.Imm(asm.R2, -68),
		asm.FnMapLookupElem.Call(), asm.JEq.Imm(asm.R0, 0, "capture_reject_return"),
		asm.LoadMem(asm.R1, asm.R0, 0, asm.DWord), asm.Add.Imm(asm.R1, 1), asm.StoreMem(asm.R0, 0, asm.R1, asm.DWord),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("capture_reject_return"), asm.Return(), asm.Mov.Reg(asm.R1, asm.R6).WithSymbol("capture_accept"))
	return out, nil
}
