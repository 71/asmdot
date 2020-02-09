// Automatically generated file.
package mips

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
)

// Bypass unused module error if we don't have assertions.
var _ = errors.New

var (
	interbuf         = [8]byte{}
	byteOrder        = binary.LittleEndian
	swappedByteOrder = binary.BigEndian
)

func write16(w io.Writer, x uint16) error {
	byteOrder.PutUint16(interbuf[:], x)
	_, err := w.Write(interbuf[:2])
	return err
}

func writeSwapped16(w io.Writer, x uint16) error {
	swappedByteOrder.PutUint16(interbuf[:], x)
	_, err := w.Write(interbuf[:2])
	return err
}

func write32(w io.Writer, x uint32) error {
	byteOrder.PutUint32(interbuf[:], x)
	_, err := w.Write(interbuf[:4])
	return err
}

func writeSwapped32(w io.Writer, x uint32) error {
	swappedByteOrder.PutUint32(interbuf[:], x)
	_, err := w.Write(interbuf[:4])
	return err
}

func write64(w io.Writer, x uint64) error {
	byteOrder.PutUint64(interbuf[:], x)
	_, err := w.Write(interbuf[:])
	return err
}

func writeSwapped64(w io.Writer, x uint64) error {
	swappedByteOrder.PutUint64(interbuf[:], x)
	_, err := w.Write(interbuf[:])
	return err
}

// A Mips register.
type Reg uint8

const (
	ZERO Reg = 0
	AT Reg = 1
	V0 Reg = 2
	V1 Reg = 3
	A0 Reg = 4
	A1 Reg = 5
	A2 Reg = 6
	A3 Reg = 7
	T0 Reg = 8
	T1 Reg = 9
	T2 Reg = 10
	T3 Reg = 11
	T4 Reg = 12
	T5 Reg = 13
	T6 Reg = 14
	T7 Reg = 15
	S0 Reg = 16
	S1 Reg = 17
	S2 Reg = 18
	S3 Reg = 19
	S4 Reg = 20
	S5 Reg = 21
	S6 Reg = 22
	S7 Reg = 23
	T8 Reg = 24
	T9 Reg = 25
	K0 Reg = 26
	K1 Reg = 27
	GP Reg = 28
	SP Reg = 29
	FP Reg = 30
	RA Reg = 31
)


func Sll(w *bytes.Buffer, rd Reg, rs Reg, rt Reg, shift uint8) error {
	if err := write32(w, uint32(((((0 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | ((uint32(rd) & 31) << 11)) | ((uint32(shift) & 31) << 6)))); err != nil {
		return err
	}
	return nil
}

func Movci(w *bytes.Buffer, rd Reg, rs Reg, rt Reg, shift uint8) error {
	if err := write32(w, uint32(((((1 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | ((uint32(rd) & 31) << 11)) | ((uint32(shift) & 31) << 6)))); err != nil {
		return err
	}
	return nil
}

func Srl(w *bytes.Buffer, rd Reg, rs Reg, rt Reg, shift uint8) error {
	if err := write32(w, uint32(((((2 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | ((uint32(rd) & 31) << 11)) | ((uint32(shift) & 31) << 6)))); err != nil {
		return err
	}
	return nil
}

func Sra(w *bytes.Buffer, rd Reg, rs Reg, rt Reg, shift uint8) error {
	if err := write32(w, uint32(((((3 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | ((uint32(rd) & 31) << 11)) | ((uint32(shift) & 31) << 6)))); err != nil {
		return err
	}
	return nil
}

func SllvR(w *bytes.Buffer, rd Reg, rs Reg, rt Reg, shift uint8) error {
	if err := write32(w, uint32(((((4 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | ((uint32(rd) & 31) << 11)) | ((uint32(shift) & 31) << 6)))); err != nil {
		return err
	}
	return nil
}

func Srlv(w *bytes.Buffer, rd Reg, rs Reg, rt Reg, shift uint8) error {
	if err := write32(w, uint32(((((6 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | ((uint32(rd) & 31) << 11)) | ((uint32(shift) & 31) << 6)))); err != nil {
		return err
	}
	return nil
}

func Srav(w *bytes.Buffer, rd Reg, rs Reg, rt Reg, shift uint8) error {
	if err := write32(w, uint32(((((7 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | ((uint32(rd) & 31) << 11)) | ((uint32(shift) & 31) << 6)))); err != nil {
		return err
	}
	return nil
}

func Jr(w *bytes.Buffer, rd Reg, rs Reg, rt Reg, shift uint8) error {
	if err := write32(w, uint32(((((8 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | ((uint32(rd) & 31) << 11)) | ((uint32(shift) & 31) << 6)))); err != nil {
		return err
	}
	return nil
}

func JalrR(w *bytes.Buffer, rd Reg, rs Reg, rt Reg, shift uint8) error {
	if err := write32(w, uint32(((((9 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | ((uint32(rd) & 31) << 11)) | ((uint32(shift) & 31) << 6)))); err != nil {
		return err
	}
	return nil
}

func Movz(w *bytes.Buffer, rd Reg, rs Reg, rt Reg, shift uint8) error {
	if err := write32(w, uint32(((((10 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | ((uint32(rd) & 31) << 11)) | ((uint32(shift) & 31) << 6)))); err != nil {
		return err
	}
	return nil
}

func Movn(w *bytes.Buffer, rd Reg, rs Reg, rt Reg, shift uint8) error {
	if err := write32(w, uint32(((((11 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | ((uint32(rd) & 31) << 11)) | ((uint32(shift) & 31) << 6)))); err != nil {
		return err
	}
	return nil
}

func Syscall(w *bytes.Buffer, rd Reg, rs Reg, rt Reg, shift uint8) error {
	if err := write32(w, uint32(((((12 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | ((uint32(rd) & 31) << 11)) | ((uint32(shift) & 31) << 6)))); err != nil {
		return err
	}
	return nil
}

func Breakpoint(w *bytes.Buffer, rd Reg, rs Reg, rt Reg, shift uint8) error {
	if err := write32(w, uint32(((((13 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | ((uint32(rd) & 31) << 11)) | ((uint32(shift) & 31) << 6)))); err != nil {
		return err
	}
	return nil
}

func Sync(w *bytes.Buffer, rd Reg, rs Reg, rt Reg, shift uint8) error {
	if err := write32(w, uint32(((((15 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | ((uint32(rd) & 31) << 11)) | ((uint32(shift) & 31) << 6)))); err != nil {
		return err
	}
	return nil
}

func Mfhi(w *bytes.Buffer, rd Reg, rs Reg, rt Reg, shift uint8) error {
	if err := write32(w, uint32(((((16 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | ((uint32(rd) & 31) << 11)) | ((uint32(shift) & 31) << 6)))); err != nil {
		return err
	}
	return nil
}

func Mthi(w *bytes.Buffer, rd Reg, rs Reg, rt Reg, shift uint8) error {
	if err := write32(w, uint32(((((17 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | ((uint32(rd) & 31) << 11)) | ((uint32(shift) & 31) << 6)))); err != nil {
		return err
	}
	return nil
}

func Mflo(w *bytes.Buffer, rd Reg, rs Reg, rt Reg, shift uint8) error {
	if err := write32(w, uint32(((((18 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | ((uint32(rd) & 31) << 11)) | ((uint32(shift) & 31) << 6)))); err != nil {
		return err
	}
	return nil
}

func DsllvR(w *bytes.Buffer, rd Reg, rs Reg, rt Reg, shift uint8) error {
	if err := write32(w, uint32(((((20 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | ((uint32(rd) & 31) << 11)) | ((uint32(shift) & 31) << 6)))); err != nil {
		return err
	}
	return nil
}

func Dsrlv(w *bytes.Buffer, rd Reg, rs Reg, rt Reg, shift uint8) error {
	if err := write32(w, uint32(((((22 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | ((uint32(rd) & 31) << 11)) | ((uint32(shift) & 31) << 6)))); err != nil {
		return err
	}
	return nil
}

func Dsrav(w *bytes.Buffer, rd Reg, rs Reg, rt Reg, shift uint8) error {
	if err := write32(w, uint32(((((23 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | ((uint32(rd) & 31) << 11)) | ((uint32(shift) & 31) << 6)))); err != nil {
		return err
	}
	return nil
}

func Mult(w *bytes.Buffer, rd Reg, rs Reg, rt Reg, shift uint8) error {
	if err := write32(w, uint32(((((24 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | ((uint32(rd) & 31) << 11)) | ((uint32(shift) & 31) << 6)))); err != nil {
		return err
	}
	return nil
}

func Multu(w *bytes.Buffer, rd Reg, rs Reg, rt Reg, shift uint8) error {
	if err := write32(w, uint32(((((25 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | ((uint32(rd) & 31) << 11)) | ((uint32(shift) & 31) << 6)))); err != nil {
		return err
	}
	return nil
}

func Div(w *bytes.Buffer, rd Reg, rs Reg, rt Reg, shift uint8) error {
	if err := write32(w, uint32(((((26 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | ((uint32(rd) & 31) << 11)) | ((uint32(shift) & 31) << 6)))); err != nil {
		return err
	}
	return nil
}

func Divu(w *bytes.Buffer, rd Reg, rs Reg, rt Reg, shift uint8) error {
	if err := write32(w, uint32(((((27 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | ((uint32(rd) & 31) << 11)) | ((uint32(shift) & 31) << 6)))); err != nil {
		return err
	}
	return nil
}

func Dmult(w *bytes.Buffer, rd Reg, rs Reg, rt Reg, shift uint8) error {
	if err := write32(w, uint32(((((28 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | ((uint32(rd) & 31) << 11)) | ((uint32(shift) & 31) << 6)))); err != nil {
		return err
	}
	return nil
}

func Dmultu(w *bytes.Buffer, rd Reg, rs Reg, rt Reg, shift uint8) error {
	if err := write32(w, uint32(((((29 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | ((uint32(rd) & 31) << 11)) | ((uint32(shift) & 31) << 6)))); err != nil {
		return err
	}
	return nil
}

func Ddiv(w *bytes.Buffer, rd Reg, rs Reg, rt Reg, shift uint8) error {
	if err := write32(w, uint32(((((30 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | ((uint32(rd) & 31) << 11)) | ((uint32(shift) & 31) << 6)))); err != nil {
		return err
	}
	return nil
}

func Ddivu(w *bytes.Buffer, rd Reg, rs Reg, rt Reg, shift uint8) error {
	if err := write32(w, uint32(((((31 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | ((uint32(rd) & 31) << 11)) | ((uint32(shift) & 31) << 6)))); err != nil {
		return err
	}
	return nil
}

func Add(w *bytes.Buffer, rd Reg, rs Reg, rt Reg, shift uint8) error {
	if err := write32(w, uint32(((((32 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | ((uint32(rd) & 31) << 11)) | ((uint32(shift) & 31) << 6)))); err != nil {
		return err
	}
	return nil
}

func Addu(w *bytes.Buffer, rd Reg, rs Reg, rt Reg, shift uint8) error {
	if err := write32(w, uint32(((((33 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | ((uint32(rd) & 31) << 11)) | ((uint32(shift) & 31) << 6)))); err != nil {
		return err
	}
	return nil
}

func Sub(w *bytes.Buffer, rd Reg, rs Reg, rt Reg, shift uint8) error {
	if err := write32(w, uint32(((((34 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | ((uint32(rd) & 31) << 11)) | ((uint32(shift) & 31) << 6)))); err != nil {
		return err
	}
	return nil
}

func Subu(w *bytes.Buffer, rd Reg, rs Reg, rt Reg, shift uint8) error {
	if err := write32(w, uint32(((((35 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | ((uint32(rd) & 31) << 11)) | ((uint32(shift) & 31) << 6)))); err != nil {
		return err
	}
	return nil
}

func And(w *bytes.Buffer, rd Reg, rs Reg, rt Reg, shift uint8) error {
	if err := write32(w, uint32(((((36 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | ((uint32(rd) & 31) << 11)) | ((uint32(shift) & 31) << 6)))); err != nil {
		return err
	}
	return nil
}

func Or(w *bytes.Buffer, rd Reg, rs Reg, rt Reg, shift uint8) error {
	if err := write32(w, uint32(((((37 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | ((uint32(rd) & 31) << 11)) | ((uint32(shift) & 31) << 6)))); err != nil {
		return err
	}
	return nil
}

func Xor(w *bytes.Buffer, rd Reg, rs Reg, rt Reg, shift uint8) error {
	if err := write32(w, uint32(((((38 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | ((uint32(rd) & 31) << 11)) | ((uint32(shift) & 31) << 6)))); err != nil {
		return err
	}
	return nil
}

func Nor(w *bytes.Buffer, rd Reg, rs Reg, rt Reg, shift uint8) error {
	if err := write32(w, uint32(((((39 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | ((uint32(rd) & 31) << 11)) | ((uint32(shift) & 31) << 6)))); err != nil {
		return err
	}
	return nil
}

func Slt(w *bytes.Buffer, rd Reg, rs Reg, rt Reg, shift uint8) error {
	if err := write32(w, uint32(((((42 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | ((uint32(rd) & 31) << 11)) | ((uint32(shift) & 31) << 6)))); err != nil {
		return err
	}
	return nil
}

func Sltu(w *bytes.Buffer, rd Reg, rs Reg, rt Reg, shift uint8) error {
	if err := write32(w, uint32(((((43 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | ((uint32(rd) & 31) << 11)) | ((uint32(shift) & 31) << 6)))); err != nil {
		return err
	}
	return nil
}

func Dadd(w *bytes.Buffer, rd Reg, rs Reg, rt Reg, shift uint8) error {
	if err := write32(w, uint32(((((44 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | ((uint32(rd) & 31) << 11)) | ((uint32(shift) & 31) << 6)))); err != nil {
		return err
	}
	return nil
}

func Daddu(w *bytes.Buffer, rd Reg, rs Reg, rt Reg, shift uint8) error {
	if err := write32(w, uint32(((((45 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | ((uint32(rd) & 31) << 11)) | ((uint32(shift) & 31) << 6)))); err != nil {
		return err
	}
	return nil
}

func Dsub(w *bytes.Buffer, rd Reg, rs Reg, rt Reg, shift uint8) error {
	if err := write32(w, uint32(((((46 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | ((uint32(rd) & 31) << 11)) | ((uint32(shift) & 31) << 6)))); err != nil {
		return err
	}
	return nil
}

func Dsubu(w *bytes.Buffer, rd Reg, rs Reg, rt Reg, shift uint8) error {
	if err := write32(w, uint32(((((47 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | ((uint32(rd) & 31) << 11)) | ((uint32(shift) & 31) << 6)))); err != nil {
		return err
	}
	return nil
}

func Tge(w *bytes.Buffer, rd Reg, rs Reg, rt Reg, shift uint8) error {
	if err := write32(w, uint32(((((48 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | ((uint32(rd) & 31) << 11)) | ((uint32(shift) & 31) << 6)))); err != nil {
		return err
	}
	return nil
}

func Tgeu(w *bytes.Buffer, rd Reg, rs Reg, rt Reg, shift uint8) error {
	if err := write32(w, uint32(((((49 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | ((uint32(rd) & 31) << 11)) | ((uint32(shift) & 31) << 6)))); err != nil {
		return err
	}
	return nil
}

func Tlt(w *bytes.Buffer, rd Reg, rs Reg, rt Reg, shift uint8) error {
	if err := write32(w, uint32(((((50 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | ((uint32(rd) & 31) << 11)) | ((uint32(shift) & 31) << 6)))); err != nil {
		return err
	}
	return nil
}

func Tltu(w *bytes.Buffer, rd Reg, rs Reg, rt Reg, shift uint8) error {
	if err := write32(w, uint32(((((51 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | ((uint32(rd) & 31) << 11)) | ((uint32(shift) & 31) << 6)))); err != nil {
		return err
	}
	return nil
}

func Teq(w *bytes.Buffer, rd Reg, rs Reg, rt Reg, shift uint8) error {
	if err := write32(w, uint32(((((52 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | ((uint32(rd) & 31) << 11)) | ((uint32(shift) & 31) << 6)))); err != nil {
		return err
	}
	return nil
}

func Tne(w *bytes.Buffer, rd Reg, rs Reg, rt Reg, shift uint8) error {
	if err := write32(w, uint32(((((54 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | ((uint32(rd) & 31) << 11)) | ((uint32(shift) & 31) << 6)))); err != nil {
		return err
	}
	return nil
}

func Dsll(w *bytes.Buffer, rd Reg, rs Reg, rt Reg, shift uint8) error {
	if err := write32(w, uint32(((((56 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | ((uint32(rd) & 31) << 11)) | ((uint32(shift) & 31) << 6)))); err != nil {
		return err
	}
	return nil
}

func Dslr(w *bytes.Buffer, rd Reg, rs Reg, rt Reg, shift uint8) error {
	if err := write32(w, uint32(((((58 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | ((uint32(rd) & 31) << 11)) | ((uint32(shift) & 31) << 6)))); err != nil {
		return err
	}
	return nil
}

func Dsra(w *bytes.Buffer, rd Reg, rs Reg, rt Reg, shift uint8) error {
	if err := write32(w, uint32(((((59 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | ((uint32(rd) & 31) << 11)) | ((uint32(shift) & 31) << 6)))); err != nil {
		return err
	}
	return nil
}

func Mhc0(w *bytes.Buffer, rd Reg, rs Reg, rt Reg, shift uint8) error {
	if err := write32(w, uint32(((((1073741824 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | ((uint32(rd) & 31) << 11)) | ((uint32(shift) & 31) << 6)))); err != nil {
		return err
	}
	return nil
}

func Btlz(w *bytes.Buffer, rs Reg, target uint16) error {
	if err := write32(w, uint32(((67108864 | ((uint32(rs) & 31) << 16)) | ((uint32(target) >> 2) & 65535)))); err != nil {
		return err
	}
	return nil
}

func Bgez(w *bytes.Buffer, rs Reg, target uint16) error {
	if err := write32(w, uint32(((67108864 | ((uint32(rs) & 31) << 16)) | ((uint32(target) >> 2) & 65535)))); err != nil {
		return err
	}
	return nil
}

func Bltzl(w *bytes.Buffer, rs Reg, target uint16) error {
	if err := write32(w, uint32(((67108864 | ((uint32(rs) & 31) << 16)) | ((uint32(target) >> 2) & 65535)))); err != nil {
		return err
	}
	return nil
}

func Bgezl(w *bytes.Buffer, rs Reg, target uint16) error {
	if err := write32(w, uint32(((67108864 | ((uint32(rs) & 31) << 16)) | ((uint32(target) >> 2) & 65535)))); err != nil {
		return err
	}
	return nil
}

func SllvRi(w *bytes.Buffer, rs Reg, target uint16) error {
	if err := write32(w, uint32(((67108864 | ((uint32(rs) & 31) << 16)) | ((uint32(target) >> 2) & 65535)))); err != nil {
		return err
	}
	return nil
}

func Tgei(w *bytes.Buffer, rs Reg, target uint16) error {
	if err := write32(w, uint32(((67108864 | ((uint32(rs) & 31) << 16)) | ((uint32(target) >> 2) & 65535)))); err != nil {
		return err
	}
	return nil
}

func JalrRi(w *bytes.Buffer, rs Reg, target uint16) error {
	if err := write32(w, uint32(((67108864 | ((uint32(rs) & 31) << 16)) | ((uint32(target) >> 2) & 65535)))); err != nil {
		return err
	}
	return nil
}

func Tlti(w *bytes.Buffer, rs Reg, target uint16) error {
	if err := write32(w, uint32(((67108864 | ((uint32(rs) & 31) << 16)) | ((uint32(target) >> 2) & 65535)))); err != nil {
		return err
	}
	return nil
}

func Tltiu(w *bytes.Buffer, rs Reg, target uint16) error {
	if err := write32(w, uint32(((67108864 | ((uint32(rs) & 31) << 16)) | ((uint32(target) >> 2) & 65535)))); err != nil {
		return err
	}
	return nil
}

func Teqi(w *bytes.Buffer, rs Reg, target uint16) error {
	if err := write32(w, uint32(((67108864 | ((uint32(rs) & 31) << 16)) | ((uint32(target) >> 2) & 65535)))); err != nil {
		return err
	}
	return nil
}

func Tnei(w *bytes.Buffer, rs Reg, target uint16) error {
	if err := write32(w, uint32(((67108864 | ((uint32(rs) & 31) << 16)) | ((uint32(target) >> 2) & 65535)))); err != nil {
		return err
	}
	return nil
}

func Bltzal(w *bytes.Buffer, rs Reg, target uint16) error {
	if err := write32(w, uint32(((67108864 | ((uint32(rs) & 31) << 16)) | ((uint32(target) >> 2) & 65535)))); err != nil {
		return err
	}
	return nil
}

func Bgezal(w *bytes.Buffer, rs Reg, target uint16) error {
	if err := write32(w, uint32(((67108864 | ((uint32(rs) & 31) << 16)) | ((uint32(target) >> 2) & 65535)))); err != nil {
		return err
	}
	return nil
}

func Bltzall(w *bytes.Buffer, rs Reg, target uint16) error {
	if err := write32(w, uint32(((67108864 | ((uint32(rs) & 31) << 16)) | ((uint32(target) >> 2) & 65535)))); err != nil {
		return err
	}
	return nil
}

func Bgezall(w *bytes.Buffer, rs Reg, target uint16) error {
	if err := write32(w, uint32(((67108864 | ((uint32(rs) & 31) << 16)) | ((uint32(target) >> 2) & 65535)))); err != nil {
		return err
	}
	return nil
}

func DsllvRi(w *bytes.Buffer, rs Reg, target uint16) error {
	if err := write32(w, uint32(((67108864 | ((uint32(rs) & 31) << 16)) | ((uint32(target) >> 2) & 65535)))); err != nil {
		return err
	}
	return nil
}

func Synci(w *bytes.Buffer, rs Reg, target uint16) error {
	if err := write32(w, uint32(((67108864 | ((uint32(rs) & 31) << 16)) | ((uint32(target) >> 2) & 65535)))); err != nil {
		return err
	}
	return nil
}

func Addi(w *bytes.Buffer, rs Reg, rt Reg, imm uint16) error {
	if err := write32(w, uint32((((536870912 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | (uint32(imm) & 65535)))); err != nil {
		return err
	}
	return nil
}

func Addiu(w *bytes.Buffer, rs Reg, rt Reg, imm uint16) error {
	if err := write32(w, uint32((((603979776 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | (uint32(imm) & 65535)))); err != nil {
		return err
	}
	return nil
}

func Andi(w *bytes.Buffer, rs Reg, rt Reg, imm uint16) error {
	if err := write32(w, uint32((((805306368 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | (uint32(imm) & 65535)))); err != nil {
		return err
	}
	return nil
}

func Beq(w *bytes.Buffer, rs Reg, rt Reg, imm uint16) error {
	if err := write32(w, uint32((((268435456 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | ((uint32(imm) & 65535) >> 2)))); err != nil {
		return err
	}
	return nil
}

func Blez(w *bytes.Buffer, rs Reg, rt Reg, imm uint16) error {
	if err := write32(w, uint32((((402653184 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | ((uint32(imm) & 65535) >> 2)))); err != nil {
		return err
	}
	return nil
}

func Bne(w *bytes.Buffer, rs Reg, rt Reg, imm uint16) error {
	if err := write32(w, uint32((((335544320 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | ((uint32(imm) & 65535) >> 2)))); err != nil {
		return err
	}
	return nil
}

func Lw(w *bytes.Buffer, rs Reg, rt Reg, imm uint16) error {
	if err := write32(w, uint32((((2348810240 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | (uint32(imm) & 65535)))); err != nil {
		return err
	}
	return nil
}

func Lbu(w *bytes.Buffer, rs Reg, rt Reg, imm uint16) error {
	if err := write32(w, uint32((((2415919104 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | (uint32(imm) & 65535)))); err != nil {
		return err
	}
	return nil
}

func Lhu(w *bytes.Buffer, rs Reg, rt Reg, imm uint16) error {
	if err := write32(w, uint32((((2483027968 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | (uint32(imm) & 65535)))); err != nil {
		return err
	}
	return nil
}

func Lui(w *bytes.Buffer, rs Reg, rt Reg, imm uint16) error {
	if err := write32(w, uint32((((1006632960 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | (uint32(imm) & 65535)))); err != nil {
		return err
	}
	return nil
}

func Ori(w *bytes.Buffer, rs Reg, rt Reg, imm uint16) error {
	if err := write32(w, uint32((((872415232 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | (uint32(imm) & 65535)))); err != nil {
		return err
	}
	return nil
}

func Sb(w *bytes.Buffer, rs Reg, rt Reg, imm uint16) error {
	if err := write32(w, uint32((((2684354560 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | (uint32(imm) & 65535)))); err != nil {
		return err
	}
	return nil
}

func Sh(w *bytes.Buffer, rs Reg, rt Reg, imm uint16) error {
	if err := write32(w, uint32((((2751463424 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | (uint32(imm) & 65535)))); err != nil {
		return err
	}
	return nil
}

func Slti(w *bytes.Buffer, rs Reg, rt Reg, imm uint16) error {
	if err := write32(w, uint32((((671088640 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | (uint32(imm) & 65535)))); err != nil {
		return err
	}
	return nil
}

func Sltiu(w *bytes.Buffer, rs Reg, rt Reg, imm uint16) error {
	if err := write32(w, uint32((((738197504 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | (uint32(imm) & 65535)))); err != nil {
		return err
	}
	return nil
}

func Sw(w *bytes.Buffer, rs Reg, rt Reg, imm uint16) error {
	if err := write32(w, uint32((((2885681152 | ((uint32(rs) & 31) << 21)) | ((uint32(rt) & 31) << 16)) | (uint32(imm) & 65535)))); err != nil {
		return err
	}
	return nil
}

func J(w *bytes.Buffer, address uint32) error {
	if err := write32(w, uint32((134217728 | ((uint32(address) >> 2) & 67108863)))); err != nil {
		return err
	}
	return nil
}

func Jal(w *bytes.Buffer, address uint32) error {
	if err := write32(w, uint32((201326592 | ((uint32(address) >> 2) & 67108863)))); err != nil {
		return err
	}
	return nil
}

