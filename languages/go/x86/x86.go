// Automatically generated file.
package x86

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


func getPrefix16(r *Reg16) byte {
	if uint8(*r) < 8 {
		return byte(*r)
	}

	*r = Reg16(uint8(*r) - 8)
	return 1
}

func getPrefix32(r *Reg32) byte {
	if uint8(*r) < 8 {
		return byte(*r)
	}

	*r = Reg32(uint8(*r) - 8)
	return 1
}

func getPrefix64(r *Reg64) byte {
	if uint8(*r) < 8 {
		return byte(*r)
	}

	*r = Reg64(uint8(*r) - 8)
	return 1
}
// An x86 8-bits register.
type Reg8 uint8

const (
	AL Reg8 = 0
	CL Reg8 = 1
	DL Reg8 = 2
	BL Reg8 = 3
	SPL Reg8 = 4
	BPL Reg8 = 5
	SIL Reg8 = 6
	DIL Reg8 = 7
	R8B Reg8 = 8
	R9B Reg8 = 9
	R10B Reg8 = 10
	R11B Reg8 = 11
	R12B Reg8 = 12
	R13B Reg8 = 13
	R14B Reg8 = 14
	R15B Reg8 = 15
)

// An x86 16-bits register.
type Reg16 uint8

const (
	AX Reg16 = 0
	CX Reg16 = 1
	DX Reg16 = 2
	BX Reg16 = 3
	SP Reg16 = 4
	BP Reg16 = 5
	SI Reg16 = 6
	DI Reg16 = 7
	R8W Reg16 = 8
	R9W Reg16 = 9
	R10W Reg16 = 10
	R11W Reg16 = 11
	R12W Reg16 = 12
	R13W Reg16 = 13
	R14W Reg16 = 14
	R15W Reg16 = 15
)

// An x86 32-bits register.
type Reg32 uint8

const (
	EAX Reg32 = 0
	ECX Reg32 = 1
	EDX Reg32 = 2
	EBX Reg32 = 3
	ESP Reg32 = 4
	EBP Reg32 = 5
	ESI Reg32 = 6
	EDI Reg32 = 7
	R8D Reg32 = 8
	R9D Reg32 = 9
	R10D Reg32 = 10
	R11D Reg32 = 11
	R12D Reg32 = 12
	R13D Reg32 = 13
	R14D Reg32 = 14
	R15D Reg32 = 15
)

// An x86 64-bits register.
type Reg64 uint8

const (
	RAX Reg64 = 0
	RCX Reg64 = 1
	RDX Reg64 = 2
	RBX Reg64 = 3
	RSP Reg64 = 4
	RBP Reg64 = 5
	RSI Reg64 = 6
	RDI Reg64 = 7
	R8 Reg64 = 8
	R9 Reg64 = 9
	R10 Reg64 = 10
	R11 Reg64 = 11
	R12 Reg64 = 12
	R13 Reg64 = 13
	R14 Reg64 = 14
	R15 Reg64 = 15
)

// An x86 128-bits register.
type Reg128 uint8

const (
)


func Pushf(w *bytes.Buffer) error {
	if err := w.WriteByte(byte(156)); err != nil {
		return err
	}
	return nil
}

func Popf(w *bytes.Buffer) error {
	if err := w.WriteByte(byte(157)); err != nil {
		return err
	}
	return nil
}

func Ret(w *bytes.Buffer) error {
	if err := w.WriteByte(byte(195)); err != nil {
		return err
	}
	return nil
}

func Clc(w *bytes.Buffer) error {
	if err := w.WriteByte(byte(248)); err != nil {
		return err
	}
	return nil
}

func Stc(w *bytes.Buffer) error {
	if err := w.WriteByte(byte(249)); err != nil {
		return err
	}
	return nil
}

func Cli(w *bytes.Buffer) error {
	if err := w.WriteByte(byte(250)); err != nil {
		return err
	}
	return nil
}

func Sti(w *bytes.Buffer) error {
	if err := w.WriteByte(byte(251)); err != nil {
		return err
	}
	return nil
}

func Cld(w *bytes.Buffer) error {
	if err := w.WriteByte(byte(252)); err != nil {
		return err
	}
	return nil
}

func Std(w *bytes.Buffer) error {
	if err := w.WriteByte(byte(253)); err != nil {
		return err
	}
	return nil
}

func JoImm8(w *bytes.Buffer, operand int8) error {
	if err := w.WriteByte(byte(112)); err != nil {
		return err
	}
	if err := w.WriteByte(byte(int8(operand))); err != nil {
		return err
	}
	return nil
}

func JnoImm8(w *bytes.Buffer, operand int8) error {
	if err := w.WriteByte(byte(113)); err != nil {
		return err
	}
	if err := w.WriteByte(byte(int8(operand))); err != nil {
		return err
	}
	return nil
}

func JbImm8(w *bytes.Buffer, operand int8) error {
	if err := w.WriteByte(byte(114)); err != nil {
		return err
	}
	if err := w.WriteByte(byte(int8(operand))); err != nil {
		return err
	}
	return nil
}

func JnaeImm8(w *bytes.Buffer, operand int8) error {
	if err := w.WriteByte(byte(114)); err != nil {
		return err
	}
	if err := w.WriteByte(byte(int8(operand))); err != nil {
		return err
	}
	return nil
}

func JcImm8(w *bytes.Buffer, operand int8) error {
	if err := w.WriteByte(byte(114)); err != nil {
		return err
	}
	if err := w.WriteByte(byte(int8(operand))); err != nil {
		return err
	}
	return nil
}

func JnbImm8(w *bytes.Buffer, operand int8) error {
	if err := w.WriteByte(byte(115)); err != nil {
		return err
	}
	if err := w.WriteByte(byte(int8(operand))); err != nil {
		return err
	}
	return nil
}

func JaeImm8(w *bytes.Buffer, operand int8) error {
	if err := w.WriteByte(byte(115)); err != nil {
		return err
	}
	if err := w.WriteByte(byte(int8(operand))); err != nil {
		return err
	}
	return nil
}

func JncImm8(w *bytes.Buffer, operand int8) error {
	if err := w.WriteByte(byte(115)); err != nil {
		return err
	}
	if err := w.WriteByte(byte(int8(operand))); err != nil {
		return err
	}
	return nil
}

func JzImm8(w *bytes.Buffer, operand int8) error {
	if err := w.WriteByte(byte(116)); err != nil {
		return err
	}
	if err := w.WriteByte(byte(int8(operand))); err != nil {
		return err
	}
	return nil
}

func JeImm8(w *bytes.Buffer, operand int8) error {
	if err := w.WriteByte(byte(116)); err != nil {
		return err
	}
	if err := w.WriteByte(byte(int8(operand))); err != nil {
		return err
	}
	return nil
}

func JnzImm8(w *bytes.Buffer, operand int8) error {
	if err := w.WriteByte(byte(117)); err != nil {
		return err
	}
	if err := w.WriteByte(byte(int8(operand))); err != nil {
		return err
	}
	return nil
}

func JneImm8(w *bytes.Buffer, operand int8) error {
	if err := w.WriteByte(byte(117)); err != nil {
		return err
	}
	if err := w.WriteByte(byte(int8(operand))); err != nil {
		return err
	}
	return nil
}

func JbeImm8(w *bytes.Buffer, operand int8) error {
	if err := w.WriteByte(byte(118)); err != nil {
		return err
	}
	if err := w.WriteByte(byte(int8(operand))); err != nil {
		return err
	}
	return nil
}

func JnaImm8(w *bytes.Buffer, operand int8) error {
	if err := w.WriteByte(byte(118)); err != nil {
		return err
	}
	if err := w.WriteByte(byte(int8(operand))); err != nil {
		return err
	}
	return nil
}

func JnbeImm8(w *bytes.Buffer, operand int8) error {
	if err := w.WriteByte(byte(119)); err != nil {
		return err
	}
	if err := w.WriteByte(byte(int8(operand))); err != nil {
		return err
	}
	return nil
}

func JaImm8(w *bytes.Buffer, operand int8) error {
	if err := w.WriteByte(byte(119)); err != nil {
		return err
	}
	if err := w.WriteByte(byte(int8(operand))); err != nil {
		return err
	}
	return nil
}

func JsImm8(w *bytes.Buffer, operand int8) error {
	if err := w.WriteByte(byte(120)); err != nil {
		return err
	}
	if err := w.WriteByte(byte(int8(operand))); err != nil {
		return err
	}
	return nil
}

func JnsImm8(w *bytes.Buffer, operand int8) error {
	if err := w.WriteByte(byte(121)); err != nil {
		return err
	}
	if err := w.WriteByte(byte(int8(operand))); err != nil {
		return err
	}
	return nil
}

func JpImm8(w *bytes.Buffer, operand int8) error {
	if err := w.WriteByte(byte(122)); err != nil {
		return err
	}
	if err := w.WriteByte(byte(int8(operand))); err != nil {
		return err
	}
	return nil
}

func JpeImm8(w *bytes.Buffer, operand int8) error {
	if err := w.WriteByte(byte(122)); err != nil {
		return err
	}
	if err := w.WriteByte(byte(int8(operand))); err != nil {
		return err
	}
	return nil
}

func JnpImm8(w *bytes.Buffer, operand int8) error {
	if err := w.WriteByte(byte(123)); err != nil {
		return err
	}
	if err := w.WriteByte(byte(int8(operand))); err != nil {
		return err
	}
	return nil
}

func JpoImm8(w *bytes.Buffer, operand int8) error {
	if err := w.WriteByte(byte(123)); err != nil {
		return err
	}
	if err := w.WriteByte(byte(int8(operand))); err != nil {
		return err
	}
	return nil
}

func JlImm8(w *bytes.Buffer, operand int8) error {
	if err := w.WriteByte(byte(124)); err != nil {
		return err
	}
	if err := w.WriteByte(byte(int8(operand))); err != nil {
		return err
	}
	return nil
}

func JngeImm8(w *bytes.Buffer, operand int8) error {
	if err := w.WriteByte(byte(124)); err != nil {
		return err
	}
	if err := w.WriteByte(byte(int8(operand))); err != nil {
		return err
	}
	return nil
}

func JnlImm8(w *bytes.Buffer, operand int8) error {
	if err := w.WriteByte(byte(125)); err != nil {
		return err
	}
	if err := w.WriteByte(byte(int8(operand))); err != nil {
		return err
	}
	return nil
}

func JgeImm8(w *bytes.Buffer, operand int8) error {
	if err := w.WriteByte(byte(125)); err != nil {
		return err
	}
	if err := w.WriteByte(byte(int8(operand))); err != nil {
		return err
	}
	return nil
}

func JleImm8(w *bytes.Buffer, operand int8) error {
	if err := w.WriteByte(byte(126)); err != nil {
		return err
	}
	if err := w.WriteByte(byte(int8(operand))); err != nil {
		return err
	}
	return nil
}

func JngImm8(w *bytes.Buffer, operand int8) error {
	if err := w.WriteByte(byte(126)); err != nil {
		return err
	}
	if err := w.WriteByte(byte(int8(operand))); err != nil {
		return err
	}
	return nil
}

func JnleImm8(w *bytes.Buffer, operand int8) error {
	if err := w.WriteByte(byte(127)); err != nil {
		return err
	}
	if err := w.WriteByte(byte(int8(operand))); err != nil {
		return err
	}
	return nil
}

func JgImm8(w *bytes.Buffer, operand int8) error {
	if err := w.WriteByte(byte(127)); err != nil {
		return err
	}
	if err := w.WriteByte(byte(int8(operand))); err != nil {
		return err
	}
	return nil
}

func IncR16(w *bytes.Buffer, operand Reg16) error {
	if err := w.WriteByte(byte((102 + getPrefix16(&operand)))); err != nil {
		return err
	}
	if err := w.WriteByte(byte((64 + uint8(operand)))); err != nil {
		return err
	}
	return nil
}

func IncR32(w *bytes.Buffer, operand Reg32) error {
	if (uint8(operand) > 7) {
		if err := w.WriteByte(byte(65)); err != nil {
			return err
		}
	}
	if err := w.WriteByte(byte((64 + uint8(operand)))); err != nil {
		return err
	}
	return nil
}

func DecR16(w *bytes.Buffer, operand Reg16) error {
	if err := w.WriteByte(byte((102 + getPrefix16(&operand)))); err != nil {
		return err
	}
	if err := w.WriteByte(byte((72 + uint8(operand)))); err != nil {
		return err
	}
	return nil
}

func DecR32(w *bytes.Buffer, operand Reg32) error {
	if (uint8(operand) > 7) {
		if err := w.WriteByte(byte(65)); err != nil {
			return err
		}
	}
	if err := w.WriteByte(byte((72 + uint8(operand)))); err != nil {
		return err
	}
	return nil
}

func PushR16(w *bytes.Buffer, operand Reg16) error {
	if err := w.WriteByte(byte((102 + getPrefix16(&operand)))); err != nil {
		return err
	}
	if err := w.WriteByte(byte((80 + uint8(operand)))); err != nil {
		return err
	}
	return nil
}

func PushR32(w *bytes.Buffer, operand Reg32) error {
	if (uint8(operand) > 7) {
		if err := w.WriteByte(byte(65)); err != nil {
			return err
		}
	}
	if err := w.WriteByte(byte((80 + uint8(operand)))); err != nil {
		return err
	}
	return nil
}

func PopR16(w *bytes.Buffer, operand Reg16) error {
	if err := w.WriteByte(byte((102 + getPrefix16(&operand)))); err != nil {
		return err
	}
	if err := w.WriteByte(byte((88 + uint8(operand)))); err != nil {
		return err
	}
	return nil
}

func PopR32(w *bytes.Buffer, operand Reg32) error {
	if (uint8(operand) > 7) {
		if err := w.WriteByte(byte(65)); err != nil {
			return err
		}
	}
	if err := w.WriteByte(byte((88 + uint8(operand)))); err != nil {
		return err
	}
	return nil
}

func PopR64(w *bytes.Buffer, operand Reg64) error {
	if err := w.WriteByte(byte((72 + getPrefix64(&operand)))); err != nil {
		return err
	}
	if err := w.WriteByte(byte((88 + uint8(operand)))); err != nil {
		return err
	}
	return nil
}

func AddRm8Imm8(w *bytes.Buffer, reg Reg8, value int8) error {
	if err := w.WriteByte(byte(128)); err != nil {
		return err
	}
	if err := w.WriteByte(byte((uint8(reg) + 0))); err != nil {
		return err
	}
	if err := w.WriteByte(byte(int8(value))); err != nil {
		return err
	}
	return nil
}

func OrRm8Imm8(w *bytes.Buffer, reg Reg8, value int8) error {
	if err := w.WriteByte(byte(128)); err != nil {
		return err
	}
	if err := w.WriteByte(byte((uint8(reg) + 1))); err != nil {
		return err
	}
	if err := w.WriteByte(byte(int8(value))); err != nil {
		return err
	}
	return nil
}

func AdcRm8Imm8(w *bytes.Buffer, reg Reg8, value int8) error {
	if err := w.WriteByte(byte(128)); err != nil {
		return err
	}
	if err := w.WriteByte(byte((uint8(reg) + 2))); err != nil {
		return err
	}
	if err := w.WriteByte(byte(int8(value))); err != nil {
		return err
	}
	return nil
}

func SbbRm8Imm8(w *bytes.Buffer, reg Reg8, value int8) error {
	if err := w.WriteByte(byte(128)); err != nil {
		return err
	}
	if err := w.WriteByte(byte((uint8(reg) + 3))); err != nil {
		return err
	}
	if err := w.WriteByte(byte(int8(value))); err != nil {
		return err
	}
	return nil
}

func AndRm8Imm8(w *bytes.Buffer, reg Reg8, value int8) error {
	if err := w.WriteByte(byte(128)); err != nil {
		return err
	}
	if err := w.WriteByte(byte((uint8(reg) + 4))); err != nil {
		return err
	}
	if err := w.WriteByte(byte(int8(value))); err != nil {
		return err
	}
	return nil
}

func SubRm8Imm8(w *bytes.Buffer, reg Reg8, value int8) error {
	if err := w.WriteByte(byte(128)); err != nil {
		return err
	}
	if err := w.WriteByte(byte((uint8(reg) + 5))); err != nil {
		return err
	}
	if err := w.WriteByte(byte(int8(value))); err != nil {
		return err
	}
	return nil
}

func XorRm8Imm8(w *bytes.Buffer, reg Reg8, value int8) error {
	if err := w.WriteByte(byte(128)); err != nil {
		return err
	}
	if err := w.WriteByte(byte((uint8(reg) + 6))); err != nil {
		return err
	}
	if err := w.WriteByte(byte(int8(value))); err != nil {
		return err
	}
	return nil
}

func CmpRm8Imm8(w *bytes.Buffer, reg Reg8, value int8) error {
	if err := w.WriteByte(byte(128)); err != nil {
		return err
	}
	if err := w.WriteByte(byte((uint8(reg) + 7))); err != nil {
		return err
	}
	if err := w.WriteByte(byte(int8(value))); err != nil {
		return err
	}
	return nil
}

func AddRm16Imm16(w *bytes.Buffer, reg Reg16, value int16) error {
	if err := w.WriteByte(byte(102)); err != nil {
		return err
	}
	if err := w.WriteByte(byte(129)); err != nil {
		return err
	}
	if err := w.WriteByte(byte((uint8(reg) + 0))); err != nil {
		return err
	}
	if err := write16(w, uint16(int16(value))); err != nil {
		return err
	}
	return nil
}

func AddRm16Imm32(w *bytes.Buffer, reg Reg16, value int32) error {
	if err := w.WriteByte(byte(102)); err != nil {
		return err
	}
	if err := w.WriteByte(byte(129)); err != nil {
		return err
	}
	if err := w.WriteByte(byte((uint8(reg) + 0))); err != nil {
		return err
	}
	if err := write32(w, uint32(int32(value))); err != nil {
		return err
	}
	return nil
}

func AddRm32Imm16(w *bytes.Buffer, reg Reg32, value int16) error {
	if err := w.WriteByte(byte(129)); err != nil {
		return err
	}
	if err := w.WriteByte(byte((uint8(reg) + 0))); err != nil {
		return err
	}
	if err := write16(w, uint16(int16(value))); err != nil {
		return err
	}
	return nil
}

func AddRm32Imm32(w *bytes.Buffer, reg Reg32, value int32) error {
	if err := w.WriteByte(byte(129)); err != nil {
		return err
	}
	if err := w.WriteByte(byte((uint8(reg) + 0))); err != nil {
		return err
	}
	if err := write32(w, uint32(int32(value))); err != nil {
		return err
	}
	return nil
}

func OrRm16Imm16(w *bytes.Buffer, reg Reg16, value int16) error {
	if err := w.WriteByte(byte(102)); err != nil {
		return err
	}
	if err := w.WriteByte(byte(129)); err != nil {
		return err
	}
	if err := w.WriteByte(byte((uint8(reg) + 1))); err != nil {
		return err
	}
	if err := write16(w, uint16(int16(value))); err != nil {
		return err
	}
	return nil
}

func OrRm16Imm32(w *bytes.Buffer, reg Reg16, value int32) error {
	if err := w.WriteByte(byte(102)); err != nil {
		return err
	}
	if err := w.WriteByte(byte(129)); err != nil {
		return err
	}
	if err := w.WriteByte(byte((uint8(reg) + 1))); err != nil {
		return err
	}
	if err := write32(w, uint32(int32(value))); err != nil {
		return err
	}
	return nil
}

func OrRm32Imm16(w *bytes.Buffer, reg Reg32, value int16) error {
	if err := w.WriteByte(byte(129)); err != nil {
		return err
	}
	if err := w.WriteByte(byte((uint8(reg) + 1))); err != nil {
		return err
	}
	if err := write16(w, uint16(int16(value))); err != nil {
		return err
	}
	return nil
}

func OrRm32Imm32(w *bytes.Buffer, reg Reg32, value int32) error {
	if err := w.WriteByte(byte(129)); err != nil {
		return err
	}
	if err := w.WriteByte(byte((uint8(reg) + 1))); err != nil {
		return err
	}
	if err := write32(w, uint32(int32(value))); err != nil {
		return err
	}
	return nil
}

func AdcRm16Imm16(w *bytes.Buffer, reg Reg16, value int16) error {
	if err := w.WriteByte(byte(102)); err != nil {
		return err
	}
	if err := w.WriteByte(byte(129)); err != nil {
		return err
	}
	if err := w.WriteByte(byte((uint8(reg) + 2))); err != nil {
		return err
	}
	if err := write16(w, uint16(int16(value))); err != nil {
		return err
	}
	return nil
}

func AdcRm16Imm32(w *bytes.Buffer, reg Reg16, value int32) error {
	if err := w.WriteByte(byte(102)); err != nil {
		return err
	}
	if err := w.WriteByte(byte(129)); err != nil {
		return err
	}
	if err := w.WriteByte(byte((uint8(reg) + 2))); err != nil {
		return err
	}
	if err := write32(w, uint32(int32(value))); err != nil {
		return err
	}
	return nil
}

func AdcRm32Imm16(w *bytes.Buffer, reg Reg32, value int16) error {
	if err := w.WriteByte(byte(129)); err != nil {
		return err
	}
	if err := w.WriteByte(byte((uint8(reg) + 2))); err != nil {
		return err
	}
	if err := write16(w, uint16(int16(value))); err != nil {
		return err
	}
	return nil
}

func AdcRm32Imm32(w *bytes.Buffer, reg Reg32, value int32) error {
	if err := w.WriteByte(byte(129)); err != nil {
		return err
	}
	if err := w.WriteByte(byte((uint8(reg) + 2))); err != nil {
		return err
	}
	if err := write32(w, uint32(int32(value))); err != nil {
		return err
	}
	return nil
}

func SbbRm16Imm16(w *bytes.Buffer, reg Reg16, value int16) error {
	if err := w.WriteByte(byte(102)); err != nil {
		return err
	}
	if err := w.WriteByte(byte(129)); err != nil {
		return err
	}
	if err := w.WriteByte(byte((uint8(reg) + 3))); err != nil {
		return err
	}
	if err := write16(w, uint16(int16(value))); err != nil {
		return err
	}
	return nil
}

func SbbRm16Imm32(w *bytes.Buffer, reg Reg16, value int32) error {
	if err := w.WriteByte(byte(102)); err != nil {
		return err
	}
	if err := w.WriteByte(byte(129)); err != nil {
		return err
	}
	if err := w.WriteByte(byte((uint8(reg) + 3))); err != nil {
		return err
	}
	if err := write32(w, uint32(int32(value))); err != nil {
		return err
	}
	return nil
}

func SbbRm32Imm16(w *bytes.Buffer, reg Reg32, value int16) error {
	if err := w.WriteByte(byte(129)); err != nil {
		return err
	}
	if err := w.WriteByte(byte((uint8(reg) + 3))); err != nil {
		return err
	}
	if err := write16(w, uint16(int16(value))); err != nil {
		return err
	}
	return nil
}

func SbbRm32Imm32(w *bytes.Buffer, reg Reg32, value int32) error {
	if err := w.WriteByte(byte(129)); err != nil {
		return err
	}
	if err := w.WriteByte(byte((uint8(reg) + 3))); err != nil {
		return err
	}
	if err := write32(w, uint32(int32(value))); err != nil {
		return err
	}
	return nil
}

func AndRm16Imm16(w *bytes.Buffer, reg Reg16, value int16) error {
	if err := w.WriteByte(byte(102)); err != nil {
		return err
	}
	if err := w.WriteByte(byte(129)); err != nil {
		return err
	}
	if err := w.WriteByte(byte((uint8(reg) + 4))); err != nil {
		return err
	}
	if err := write16(w, uint16(int16(value))); err != nil {
		return err
	}
	return nil
}

func AndRm16Imm32(w *bytes.Buffer, reg Reg16, value int32) error {
	if err := w.WriteByte(byte(102)); err != nil {
		return err
	}
	if err := w.WriteByte(byte(129)); err != nil {
		return err
	}
	if err := w.WriteByte(byte((uint8(reg) + 4))); err != nil {
		return err
	}
	if err := write32(w, uint32(int32(value))); err != nil {
		return err
	}
	return nil
}

func AndRm32Imm16(w *bytes.Buffer, reg Reg32, value int16) error {
	if err := w.WriteByte(byte(129)); err != nil {
		return err
	}
	if err := w.WriteByte(byte((uint8(reg) + 4))); err != nil {
		return err
	}
	if err := write16(w, uint16(int16(value))); err != nil {
		return err
	}
	return nil
}

func AndRm32Imm32(w *bytes.Buffer, reg Reg32, value int32) error {
	if err := w.WriteByte(byte(129)); err != nil {
		return err
	}
	if err := w.WriteByte(byte((uint8(reg) + 4))); err != nil {
		return err
	}
	if err := write32(w, uint32(int32(value))); err != nil {
		return err
	}
	return nil
}

func SubRm16Imm16(w *bytes.Buffer, reg Reg16, value int16) error {
	if err := w.WriteByte(byte(102)); err != nil {
		return err
	}
	if err := w.WriteByte(byte(129)); err != nil {
		return err
	}
	if err := w.WriteByte(byte((uint8(reg) + 5))); err != nil {
		return err
	}
	if err := write16(w, uint16(int16(value))); err != nil {
		return err
	}
	return nil
}

func SubRm16Imm32(w *bytes.Buffer, reg Reg16, value int32) error {
	if err := w.WriteByte(byte(102)); err != nil {
		return err
	}
	if err := w.WriteByte(byte(129)); err != nil {
		return err
	}
	if err := w.WriteByte(byte((uint8(reg) + 5))); err != nil {
		return err
	}
	if err := write32(w, uint32(int32(value))); err != nil {
		return err
	}
	return nil
}

func SubRm32Imm16(w *bytes.Buffer, reg Reg32, value int16) error {
	if err := w.WriteByte(byte(129)); err != nil {
		return err
	}
	if err := w.WriteByte(byte((uint8(reg) + 5))); err != nil {
		return err
	}
	if err := write16(w, uint16(int16(value))); err != nil {
		return err
	}
	return nil
}

func SubRm32Imm32(w *bytes.Buffer, reg Reg32, value int32) error {
	if err := w.WriteByte(byte(129)); err != nil {
		return err
	}
	if err := w.WriteByte(byte((uint8(reg) + 5))); err != nil {
		return err
	}
	if err := write32(w, uint32(int32(value))); err != nil {
		return err
	}
	return nil
}

func XorRm16Imm16(w *bytes.Buffer, reg Reg16, value int16) error {
	if err := w.WriteByte(byte(102)); err != nil {
		return err
	}
	if err := w.WriteByte(byte(129)); err != nil {
		return err
	}
	if err := w.WriteByte(byte((uint8(reg) + 6))); err != nil {
		return err
	}
	if err := write16(w, uint16(int16(value))); err != nil {
		return err
	}
	return nil
}

func XorRm16Imm32(w *bytes.Buffer, reg Reg16, value int32) error {
	if err := w.WriteByte(byte(102)); err != nil {
		return err
	}
	if err := w.WriteByte(byte(129)); err != nil {
		return err
	}
	if err := w.WriteByte(byte((uint8(reg) + 6))); err != nil {
		return err
	}
	if err := write32(w, uint32(int32(value))); err != nil {
		return err
	}
	return nil
}

func XorRm32Imm16(w *bytes.Buffer, reg Reg32, value int16) error {
	if err := w.WriteByte(byte(129)); err != nil {
		return err
	}
	if err := w.WriteByte(byte((uint8(reg) + 6))); err != nil {
		return err
	}
	if err := write16(w, uint16(int16(value))); err != nil {
		return err
	}
	return nil
}

func XorRm32Imm32(w *bytes.Buffer, reg Reg32, value int32) error {
	if err := w.WriteByte(byte(129)); err != nil {
		return err
	}
	if err := w.WriteByte(byte((uint8(reg) + 6))); err != nil {
		return err
	}
	if err := write32(w, uint32(int32(value))); err != nil {
		return err
	}
	return nil
}

func CmpRm16Imm16(w *bytes.Buffer, reg Reg16, value int16) error {
	if err := w.WriteByte(byte(102)); err != nil {
		return err
	}
	if err := w.WriteByte(byte(129)); err != nil {
		return err
	}
	if err := w.WriteByte(byte((uint8(reg) + 7))); err != nil {
		return err
	}
	if err := write16(w, uint16(int16(value))); err != nil {
		return err
	}
	return nil
}

func CmpRm16Imm32(w *bytes.Buffer, reg Reg16, value int32) error {
	if err := w.WriteByte(byte(102)); err != nil {
		return err
	}
	if err := w.WriteByte(byte(129)); err != nil {
		return err
	}
	if err := w.WriteByte(byte((uint8(reg) + 7))); err != nil {
		return err
	}
	if err := write32(w, uint32(int32(value))); err != nil {
		return err
	}
	return nil
}

func CmpRm32Imm16(w *bytes.Buffer, reg Reg32, value int16) error {
	if err := w.WriteByte(byte(129)); err != nil {
		return err
	}
	if err := w.WriteByte(byte((uint8(reg) + 7))); err != nil {
		return err
	}
	if err := write16(w, uint16(int16(value))); err != nil {
		return err
	}
	return nil
}

func CmpRm32Imm32(w *bytes.Buffer, reg Reg32, value int32) error {
	if err := w.WriteByte(byte(129)); err != nil {
		return err
	}
	if err := w.WriteByte(byte((uint8(reg) + 7))); err != nil {
		return err
	}
	if err := write32(w, uint32(int32(value))); err != nil {
		return err
	}
	return nil
}

func AddRm16Imm8(w *bytes.Buffer, reg Reg16, value int8) error {
	if err := w.WriteByte(byte(102)); err != nil {
		return err
	}
	if err := w.WriteByte(byte(131)); err != nil {
		return err
	}
	if err := w.WriteByte(byte((uint8(reg) + 0))); err != nil {
		return err
	}
	if err := w.WriteByte(byte(int8(value))); err != nil {
		return err
	}
	return nil
}

func AddRm32Imm8(w *bytes.Buffer, reg Reg32, value int8) error {
	if err := w.WriteByte(byte(131)); err != nil {
		return err
	}
	if err := w.WriteByte(byte((uint8(reg) + 0))); err != nil {
		return err
	}
	if err := w.WriteByte(byte(int8(value))); err != nil {
		return err
	}
	return nil
}

func OrRm16Imm8(w *bytes.Buffer, reg Reg16, value int8) error {
	if err := w.WriteByte(byte(102)); err != nil {
		return err
	}
	if err := w.WriteByte(byte(131)); err != nil {
		return err
	}
	if err := w.WriteByte(byte((uint8(reg) + 1))); err != nil {
		return err
	}
	if err := w.WriteByte(byte(int8(value))); err != nil {
		return err
	}
	return nil
}

func OrRm32Imm8(w *bytes.Buffer, reg Reg32, value int8) error {
	if err := w.WriteByte(byte(131)); err != nil {
		return err
	}
	if err := w.WriteByte(byte((uint8(reg) + 1))); err != nil {
		return err
	}
	if err := w.WriteByte(byte(int8(value))); err != nil {
		return err
	}
	return nil
}

func AdcRm16Imm8(w *bytes.Buffer, reg Reg16, value int8) error {
	if err := w.WriteByte(byte(102)); err != nil {
		return err
	}
	if err := w.WriteByte(byte(131)); err != nil {
		return err
	}
	if err := w.WriteByte(byte((uint8(reg) + 2))); err != nil {
		return err
	}
	if err := w.WriteByte(byte(int8(value))); err != nil {
		return err
	}
	return nil
}

func AdcRm32Imm8(w *bytes.Buffer, reg Reg32, value int8) error {
	if err := w.WriteByte(byte(131)); err != nil {
		return err
	}
	if err := w.WriteByte(byte((uint8(reg) + 2))); err != nil {
		return err
	}
	if err := w.WriteByte(byte(int8(value))); err != nil {
		return err
	}
	return nil
}

func SbbRm16Imm8(w *bytes.Buffer, reg Reg16, value int8) error {
	if err := w.WriteByte(byte(102)); err != nil {
		return err
	}
	if err := w.WriteByte(byte(131)); err != nil {
		return err
	}
	if err := w.WriteByte(byte((uint8(reg) + 3))); err != nil {
		return err
	}
	if err := w.WriteByte(byte(int8(value))); err != nil {
		return err
	}
	return nil
}

func SbbRm32Imm8(w *bytes.Buffer, reg Reg32, value int8) error {
	if err := w.WriteByte(byte(131)); err != nil {
		return err
	}
	if err := w.WriteByte(byte((uint8(reg) + 3))); err != nil {
		return err
	}
	if err := w.WriteByte(byte(int8(value))); err != nil {
		return err
	}
	return nil
}

func AndRm16Imm8(w *bytes.Buffer, reg Reg16, value int8) error {
	if err := w.WriteByte(byte(102)); err != nil {
		return err
	}
	if err := w.WriteByte(byte(131)); err != nil {
		return err
	}
	if err := w.WriteByte(byte((uint8(reg) + 4))); err != nil {
		return err
	}
	if err := w.WriteByte(byte(int8(value))); err != nil {
		return err
	}
	return nil
}

func AndRm32Imm8(w *bytes.Buffer, reg Reg32, value int8) error {
	if err := w.WriteByte(byte(131)); err != nil {
		return err
	}
	if err := w.WriteByte(byte((uint8(reg) + 4))); err != nil {
		return err
	}
	if err := w.WriteByte(byte(int8(value))); err != nil {
		return err
	}
	return nil
}

func SubRm16Imm8(w *bytes.Buffer, reg Reg16, value int8) error {
	if err := w.WriteByte(byte(102)); err != nil {
		return err
	}
	if err := w.WriteByte(byte(131)); err != nil {
		return err
	}
	if err := w.WriteByte(byte((uint8(reg) + 5))); err != nil {
		return err
	}
	if err := w.WriteByte(byte(int8(value))); err != nil {
		return err
	}
	return nil
}

func SubRm32Imm8(w *bytes.Buffer, reg Reg32, value int8) error {
	if err := w.WriteByte(byte(131)); err != nil {
		return err
	}
	if err := w.WriteByte(byte((uint8(reg) + 5))); err != nil {
		return err
	}
	if err := w.WriteByte(byte(int8(value))); err != nil {
		return err
	}
	return nil
}

func XorRm16Imm8(w *bytes.Buffer, reg Reg16, value int8) error {
	if err := w.WriteByte(byte(102)); err != nil {
		return err
	}
	if err := w.WriteByte(byte(131)); err != nil {
		return err
	}
	if err := w.WriteByte(byte((uint8(reg) + 6))); err != nil {
		return err
	}
	if err := w.WriteByte(byte(int8(value))); err != nil {
		return err
	}
	return nil
}

func XorRm32Imm8(w *bytes.Buffer, reg Reg32, value int8) error {
	if err := w.WriteByte(byte(131)); err != nil {
		return err
	}
	if err := w.WriteByte(byte((uint8(reg) + 6))); err != nil {
		return err
	}
	if err := w.WriteByte(byte(int8(value))); err != nil {
		return err
	}
	return nil
}

func CmpRm16Imm8(w *bytes.Buffer, reg Reg16, value int8) error {
	if err := w.WriteByte(byte(102)); err != nil {
		return err
	}
	if err := w.WriteByte(byte(131)); err != nil {
		return err
	}
	if err := w.WriteByte(byte((uint8(reg) + 7))); err != nil {
		return err
	}
	if err := w.WriteByte(byte(int8(value))); err != nil {
		return err
	}
	return nil
}

func CmpRm32Imm8(w *bytes.Buffer, reg Reg32, value int8) error {
	if err := w.WriteByte(byte(131)); err != nil {
		return err
	}
	if err := w.WriteByte(byte((uint8(reg) + 7))); err != nil {
		return err
	}
	if err := w.WriteByte(byte(int8(value))); err != nil {
		return err
	}
	return nil
}

