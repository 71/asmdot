// Automatically generated file.
package arm

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

// An ARM register.
type Reg uint8

const (
	R0 Reg = 0
	R1 Reg = 1
	R2 Reg = 2
	R3 Reg = 3
	R4 Reg = 4
	R5 Reg = 5
	R6 Reg = 6
	R7 Reg = 7
	R8 Reg = 8
	R9 Reg = 9
	R10 Reg = 10
	R11 Reg = 11
	R12 Reg = 12
	R13 Reg = 13
	R14 Reg = 14
	R15 Reg = 15
	A1 Reg = 0
	A2 Reg = 1
	A3 Reg = 2
	A4 Reg = 3
	V1 Reg = 4
	V2 Reg = 5
	V3 Reg = 6
	V4 Reg = 7
	V5 Reg = 8
	V6 Reg = 9
	V7 Reg = 10
	V8 Reg = 11
	IP Reg = 12
	SP Reg = 13
	LR Reg = 14
	PC Reg = 15
	WR Reg = 7
	SB Reg = 9
	SL Reg = 10
	FP Reg = 11
)

// A list of ARM registers, where each register corresponds to a single bit.
type RegList uint16

const (
	// Register #1.
	RLR0 RegList = 0
	// Register #2.
	RLR1 RegList = 1
	// Register #3.
	RLR2 RegList = 2
	// Register #4.
	RLR3 RegList = 3
	// Register #5.
	RLR4 RegList = 4
	// Register #6.
	RLR5 RegList = 5
	// Register #7.
	RLR6 RegList = 6
	// Register #8.
	RLR7 RegList = 7
	// Register #9.
	RLR8 RegList = 8
	// Register #10.
	RLR9 RegList = 9
	// Register #11.
	RLR10 RegList = 10
	// Register #12.
	RLR11 RegList = 11
	// Register #13.
	RLR12 RegList = 12
	// Register #14.
	RLR13 RegList = 13
	// Register #15.
	RLR14 RegList = 14
	// Register #16.
	RLR15 RegList = 15
	// Register A1.
	RLA1 RegList = 0
	// Register A2.
	RLA2 RegList = 1
	// Register A3.
	RLA3 RegList = 2
	// Register A4.
	RLA4 RegList = 3
	// Register V1.
	RLV1 RegList = 4
	// Register V2.
	RLV2 RegList = 5
	// Register V3.
	RLV3 RegList = 6
	// Register V4.
	RLV4 RegList = 7
	// Register V5.
	RLV5 RegList = 8
	// Register V6.
	RLV6 RegList = 9
	// Register V7.
	RLV7 RegList = 10
	// Register V8.
	RLV8 RegList = 11
	// Register IP.
	RLIP RegList = 12
	// Register SP.
	RLSP RegList = 13
	// Register LR.
	RLLR RegList = 14
	// Register PC.
	RLPC RegList = 15
	// Register WR.
	RLWR RegList = 7
	// Register SB.
	RLSB RegList = 9
	// Register SL.
	RLSL RegList = 10
	// Register FP.
	RLFP RegList = 11
)

// An ARM coprocessor.
type Coprocessor uint8

const (
	CP0 Coprocessor = 0
	CP1 Coprocessor = 1
	CP2 Coprocessor = 2
	CP3 Coprocessor = 3
	CP4 Coprocessor = 4
	CP5 Coprocessor = 5
	CP6 Coprocessor = 6
	CP7 Coprocessor = 7
	CP8 Coprocessor = 8
	CP9 Coprocessor = 9
	CP10 Coprocessor = 10
	CP11 Coprocessor = 11
	CP12 Coprocessor = 12
	CP13 Coprocessor = 13
	CP14 Coprocessor = 14
	CP15 Coprocessor = 15
)

// Condition for an ARM instruction to be executed.
type Condition uint8

const (
	// Equal.
	Equal Condition = 0
	// Not equal.
	NotEqual Condition = 1
	// Unsigned higher or same.
	UnsignedHigherOrEqual Condition = 2
	// Unsigned lower.
	UnsignedLower Condition = 3
	// Minus / negative.
	Negative Condition = 4
	// Plus / positive or zero.
	PositiveOrZero Condition = 5
	// Overflow.
	Overflow Condition = 6
	// No overflow.
	NoOverflow Condition = 7
	// Unsigned higher.
	UnsignedHigher Condition = 8
	// Unsigned lower or same.
	UnsignedLowerOrEqual Condition = 9
	// Signed greater than or equal.
	SignedGreaterOrEqual Condition = 10
	// Signed less than.
	SignedLower Condition = 11
	// Signed greater than.
	SignedGreater Condition = 12
	// Signed less than or equal.
	SignedLowerOrEqual Condition = 13
	// Always (unconditional).
	Always Condition = 14
	// Unpredictable (ARMv4 or lower).
	Unpredictable Condition = 15
	// Carry set.
	CarrySet Condition = 2
	// Carry clear.
	CarryClear Condition = 3
)

// Processor mode.
type Mode uint8

const (
	// User mode.
	USRMode Mode = 16
	// FIQ (high-speed data transfer) mode.
	FIQMode Mode = 17
	// IRQ (general-purpose interrupt handling) mode.
	IRQMode Mode = 18
	// Supervisor mode.
	SVCMode Mode = 19
	// Abort mode.
	ABTMode Mode = 23
	// Undefined mode.
	UNDMode Mode = 27
	// System (privileged) mode.
	SYSMode Mode = 31
)

// Kind of a shift.
type Shift uint8

const (
	// Logical shift left.
	LogicalShiftLeft Shift = 0
	// Logical shift right.
	LogicalShiftRight Shift = 1
	// Arithmetic shift right.
	ArithShiftRight Shift = 2
	// Rotate right.
	RotateRight Shift = 3
	// Shifted right by one bit.
	RRX Shift = 3
)

// Kind of a right rotation.
type Rotation uint8

const (
	// Do not rotate.
	NoRotation Rotation = 0
	// Rotate 8 bits to the right.
	RotateRight8 Rotation = 1
	// Rotate 16 bits to the right.
	RotateRight16 Rotation = 2
	// Rotate 24 bits to the right.
	RotateRight24 Rotation = 3
)

// Field mask bits.
type FieldMask uint8

const (
	// Control field mask bit.
	CFieldMask FieldMask = 1
	// Extension field mask bit.
	XFieldMask FieldMask = 2
	// Status field mask bit.
	SFieldMask FieldMask = 4
	// Flags field mask bit.
	FFieldMask FieldMask = 8
)

// Interrupt flags.
type InterruptFlags uint8

const (
	// FIQ interrupt bit.
	InterruptFIQ InterruptFlags = 1
	// IRQ interrupt bit.
	InterruptIRQ InterruptFlags = 2
	// Imprecise data abort bit.
	ImpreciseDataAbort InterruptFlags = 4
)

// Addressing type.
type Addressing uint8

const (
	// Post-indexed addressing.
	PostIndexedIndexing Addressing = 0
	// Pre-indexed addressing (or offset addressing if `write` is false).
	PreIndexedIndexing Addressing = 1
	// Offset addressing (or pre-indexed addressing if `write` is true).
	OffsetIndexing Addressing = 1
)

// Offset adding or subtracting mode.
type OffsetMode uint8

const (
	// Subtract offset from the base.
	SubtractOffset OffsetMode = 0
	// Add offset to the base.
	AddOffset OffsetMode = 1
)


func Adc(w *bytes.Buffer, cond Condition, updateCprs bool, rn Reg, rd Reg, updateCondition bool) error {
	var updateCprs_ uint32 = 0
	if updateCprs {
		updateCprs_ = 1
	}
	var updateCondition_ uint32 = 0
	if updateCondition {
		updateCondition_ = 1
	}
	if err := write32(w, uint32((((((10485760 | uint32(cond)) | (updateCprs_ << 20)) | (uint32(rn) << 16)) | (uint32(rd) << 12)) | (updateCondition_ << 20)))); err != nil {
		return err
	}
	return nil
}

func Add(w *bytes.Buffer, cond Condition, updateCprs bool, rn Reg, rd Reg, updateCondition bool) error {
	var updateCprs_ uint32 = 0
	if updateCprs {
		updateCprs_ = 1
	}
	var updateCondition_ uint32 = 0
	if updateCondition {
		updateCondition_ = 1
	}
	if err := write32(w, uint32((((((8388608 | uint32(cond)) | (updateCprs_ << 20)) | (uint32(rn) << 16)) | (uint32(rd) << 12)) | (updateCondition_ << 20)))); err != nil {
		return err
	}
	return nil
}

func And(w *bytes.Buffer, cond Condition, updateCprs bool, rn Reg, rd Reg, updateCondition bool) error {
	var updateCprs_ uint32 = 0
	if updateCprs {
		updateCprs_ = 1
	}
	var updateCondition_ uint32 = 0
	if updateCondition {
		updateCondition_ = 1
	}
	if err := write32(w, uint32((((((0 | uint32(cond)) | (updateCprs_ << 20)) | (uint32(rn) << 16)) | (uint32(rd) << 12)) | (updateCondition_ << 20)))); err != nil {
		return err
	}
	return nil
}

func Eor(w *bytes.Buffer, cond Condition, updateCprs bool, rn Reg, rd Reg, updateCondition bool) error {
	var updateCprs_ uint32 = 0
	if updateCprs {
		updateCprs_ = 1
	}
	var updateCondition_ uint32 = 0
	if updateCondition {
		updateCondition_ = 1
	}
	if err := write32(w, uint32((((((2097152 | uint32(cond)) | (updateCprs_ << 20)) | (uint32(rn) << 16)) | (uint32(rd) << 12)) | (updateCondition_ << 20)))); err != nil {
		return err
	}
	return nil
}

func Orr(w *bytes.Buffer, cond Condition, updateCprs bool, rn Reg, rd Reg, updateCondition bool) error {
	var updateCprs_ uint32 = 0
	if updateCprs {
		updateCprs_ = 1
	}
	var updateCondition_ uint32 = 0
	if updateCondition {
		updateCondition_ = 1
	}
	if err := write32(w, uint32((((((25165824 | uint32(cond)) | (updateCprs_ << 20)) | (uint32(rn) << 16)) | (uint32(rd) << 12)) | (updateCondition_ << 20)))); err != nil {
		return err
	}
	return nil
}

func Rsb(w *bytes.Buffer, cond Condition, updateCprs bool, rn Reg, rd Reg, updateCondition bool) error {
	var updateCprs_ uint32 = 0
	if updateCprs {
		updateCprs_ = 1
	}
	var updateCondition_ uint32 = 0
	if updateCondition {
		updateCondition_ = 1
	}
	if err := write32(w, uint32((((((6291456 | uint32(cond)) | (updateCprs_ << 20)) | (uint32(rn) << 16)) | (uint32(rd) << 12)) | (updateCondition_ << 20)))); err != nil {
		return err
	}
	return nil
}

func Rsc(w *bytes.Buffer, cond Condition, updateCprs bool, rn Reg, rd Reg, updateCondition bool) error {
	var updateCprs_ uint32 = 0
	if updateCprs {
		updateCprs_ = 1
	}
	var updateCondition_ uint32 = 0
	if updateCondition {
		updateCondition_ = 1
	}
	if err := write32(w, uint32((((((14680064 | uint32(cond)) | (updateCprs_ << 20)) | (uint32(rn) << 16)) | (uint32(rd) << 12)) | (updateCondition_ << 20)))); err != nil {
		return err
	}
	return nil
}

func Sbc(w *bytes.Buffer, cond Condition, updateCprs bool, rn Reg, rd Reg, updateCondition bool) error {
	var updateCprs_ uint32 = 0
	if updateCprs {
		updateCprs_ = 1
	}
	var updateCondition_ uint32 = 0
	if updateCondition {
		updateCondition_ = 1
	}
	if err := write32(w, uint32((((((12582912 | uint32(cond)) | (updateCprs_ << 20)) | (uint32(rn) << 16)) | (uint32(rd) << 12)) | (updateCondition_ << 20)))); err != nil {
		return err
	}
	return nil
}

func Sub(w *bytes.Buffer, cond Condition, updateCprs bool, rn Reg, rd Reg, updateCondition bool) error {
	var updateCprs_ uint32 = 0
	if updateCprs {
		updateCprs_ = 1
	}
	var updateCondition_ uint32 = 0
	if updateCondition {
		updateCondition_ = 1
	}
	if err := write32(w, uint32((((((4194304 | uint32(cond)) | (updateCprs_ << 20)) | (uint32(rn) << 16)) | (uint32(rd) << 12)) | (updateCondition_ << 20)))); err != nil {
		return err
	}
	return nil
}

func Bkpt(w *bytes.Buffer, immed uint16) error {
	if err := write32(w, uint32(((3776970864 | ((uint32(immed) & 65520) << 8)) | ((uint32(immed) & 15) << 0)))); err != nil {
		return err
	}
	return nil
}

func B(w *bytes.Buffer, cond Condition) error {
	if err := write32(w, uint32((167772160 | uint32(cond)))); err != nil {
		return err
	}
	return nil
}

func Bic(w *bytes.Buffer, cond Condition, updateCprs bool, rn Reg, rd Reg, updateCondition bool) error {
	var updateCprs_ uint32 = 0
	if updateCprs {
		updateCprs_ = 1
	}
	var updateCondition_ uint32 = 0
	if updateCondition {
		updateCondition_ = 1
	}
	if err := write32(w, uint32((((((29360128 | uint32(cond)) | (updateCprs_ << 20)) | (uint32(rn) << 16)) | (uint32(rd) << 12)) | (updateCondition_ << 20)))); err != nil {
		return err
	}
	return nil
}

func Blx(w *bytes.Buffer, cond Condition) error {
	if err := write32(w, uint32((19922736 | uint32(cond)))); err != nil {
		return err
	}
	return nil
}

func Bx(w *bytes.Buffer, cond Condition) error {
	if err := write32(w, uint32((19922704 | uint32(cond)))); err != nil {
		return err
	}
	return nil
}

func Bxj(w *bytes.Buffer, cond Condition) error {
	if err := write32(w, uint32((19922720 | uint32(cond)))); err != nil {
		return err
	}
	return nil
}

func Blxun(w *bytes.Buffer) error {
	if err := write32(w, uint32(4194304000)); err != nil {
		return err
	}
	return nil
}

func Clz(w *bytes.Buffer, cond Condition, rd Reg) error {
	if err := write32(w, uint32(((24055568 | uint32(cond)) | (uint32(rd) << 12)))); err != nil {
		return err
	}
	return nil
}

func Cmn(w *bytes.Buffer, cond Condition, rn Reg) error {
	if err := write32(w, uint32(((24117248 | uint32(cond)) | (uint32(rn) << 16)))); err != nil {
		return err
	}
	return nil
}

func Cmp(w *bytes.Buffer, cond Condition, rn Reg) error {
	if err := write32(w, uint32(((22020096 | uint32(cond)) | (uint32(rn) << 16)))); err != nil {
		return err
	}
	return nil
}

func Cpy(w *bytes.Buffer, cond Condition, rd Reg) error {
	if err := write32(w, uint32(((27262976 | uint32(cond)) | (uint32(rd) << 12)))); err != nil {
		return err
	}
	return nil
}

func Cps(w *bytes.Buffer, mode Mode) error {
	if err := write32(w, uint32((4043440128 | (uint32(mode) << 0)))); err != nil {
		return err
	}
	return nil
}

func Cpsie(w *bytes.Buffer, iflags InterruptFlags) error {
	if err := write32(w, uint32((4043833344 | (uint32(iflags) << 6)))); err != nil {
		return err
	}
	return nil
}

func Cpsid(w *bytes.Buffer, iflags InterruptFlags) error {
	if err := write32(w, uint32((4044095488 | (uint32(iflags) << 6)))); err != nil {
		return err
	}
	return nil
}

func CpsieMode(w *bytes.Buffer, iflags InterruptFlags, mode Mode) error {
	if err := write32(w, uint32(((4043964416 | (uint32(iflags) << 6)) | (uint32(mode) << 0)))); err != nil {
		return err
	}
	return nil
}

func CpsidMode(w *bytes.Buffer, iflags InterruptFlags, mode Mode) error {
	if err := write32(w, uint32(((4044226560 | (uint32(iflags) << 6)) | (uint32(mode) << 0)))); err != nil {
		return err
	}
	return nil
}

func Ldc(w *bytes.Buffer, cond Condition, write bool, rn Reg, cpnum Coprocessor, offsetMode OffsetMode, addressingMode Addressing) error {
	var write_ uint32 = 0
	if write {
		write_ = 1
	}
	if err := write32(w, uint32(((((((202375168 | uint32(cond)) | (write_ << 21)) | (uint32(rn) << 16)) | (uint32(cpnum) << 8)) | (uint32(addressingMode) << 23)) | (uint32(offsetMode) << 11)))); err != nil {
		return err
	}
	return nil
}

func Ldm(w *bytes.Buffer, cond Condition, rn Reg, offsetMode OffsetMode, addressingMode Addressing, registers RegList, write bool, copySpsr bool) error {
	var write_ uint32 = 0
	if write {
		write_ = 1
	}
	var copySpsr_ uint32 = 0
	if copySpsr {
		copySpsr_ = 1
	}
	if !((copySpsr_ == 1) != (write_ == (uint32(registers) & 32768))) {
		return errors.New("Failed precondition: ((copySpsr_ == 1) != (write_ == (uint32(registers) & 32768))).")
	}
	if err := write32(w, uint32(((((((((135266304 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(addressingMode) << 23)) | (uint32(offsetMode) << 11)) | (uint32(addressingMode) << 23)) | uint32(registers)) | (copySpsr_ << 21)) | (write_ << 10)))); err != nil {
		return err
	}
	return nil
}

func Ldr(w *bytes.Buffer, cond Condition, write bool, rn Reg, rd Reg, offsetMode OffsetMode, addressingMode Addressing) error {
	var write_ uint32 = 0
	if write {
		write_ = 1
	}
	if err := write32(w, uint32(((((((68157440 | uint32(cond)) | (write_ << 21)) | (uint32(rn) << 16)) | (uint32(rd) << 12)) | (uint32(addressingMode) << 23)) | (uint32(offsetMode) << 11)))); err != nil {
		return err
	}
	return nil
}

func Ldrb(w *bytes.Buffer, cond Condition, write bool, rn Reg, rd Reg, offsetMode OffsetMode, addressingMode Addressing) error {
	var write_ uint32 = 0
	if write {
		write_ = 1
	}
	if err := write32(w, uint32(((((((72351744 | uint32(cond)) | (write_ << 21)) | (uint32(rn) << 16)) | (uint32(rd) << 12)) | (uint32(addressingMode) << 23)) | (uint32(offsetMode) << 11)))); err != nil {
		return err
	}
	return nil
}

func Ldrbt(w *bytes.Buffer, cond Condition, rn Reg, rd Reg, offsetMode OffsetMode) error {
	if err := write32(w, uint32(((((74448896 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)) | (uint32(offsetMode) << 23)))); err != nil {
		return err
	}
	return nil
}

func Ldrd(w *bytes.Buffer, cond Condition, write bool, rn Reg, rd Reg, offsetMode OffsetMode, addressingMode Addressing) error {
	var write_ uint32 = 0
	if write {
		write_ = 1
	}
	if err := write32(w, uint32(((((((208 | uint32(cond)) | (write_ << 21)) | (uint32(rn) << 16)) | (uint32(rd) << 12)) | (uint32(addressingMode) << 23)) | (uint32(offsetMode) << 11)))); err != nil {
		return err
	}
	return nil
}

func Ldrex(w *bytes.Buffer, cond Condition, rn Reg, rd Reg) error {
	if err := write32(w, uint32((((26218399 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)))); err != nil {
		return err
	}
	return nil
}

func Ldrh(w *bytes.Buffer, cond Condition, write bool, rn Reg, rd Reg, offsetMode OffsetMode, addressingMode Addressing) error {
	var write_ uint32 = 0
	if write {
		write_ = 1
	}
	if err := write32(w, uint32(((((((1048752 | uint32(cond)) | (write_ << 21)) | (uint32(rn) << 16)) | (uint32(rd) << 12)) | (uint32(addressingMode) << 23)) | (uint32(offsetMode) << 11)))); err != nil {
		return err
	}
	return nil
}

func Ldrsb(w *bytes.Buffer, cond Condition, write bool, rn Reg, rd Reg, offsetMode OffsetMode, addressingMode Addressing) error {
	var write_ uint32 = 0
	if write {
		write_ = 1
	}
	if err := write32(w, uint32(((((((1048784 | uint32(cond)) | (write_ << 21)) | (uint32(rn) << 16)) | (uint32(rd) << 12)) | (uint32(addressingMode) << 23)) | (uint32(offsetMode) << 11)))); err != nil {
		return err
	}
	return nil
}

func Ldrsh(w *bytes.Buffer, cond Condition, write bool, rn Reg, rd Reg, offsetMode OffsetMode, addressingMode Addressing) error {
	var write_ uint32 = 0
	if write {
		write_ = 1
	}
	if err := write32(w, uint32(((((((1048816 | uint32(cond)) | (write_ << 21)) | (uint32(rn) << 16)) | (uint32(rd) << 12)) | (uint32(addressingMode) << 23)) | (uint32(offsetMode) << 11)))); err != nil {
		return err
	}
	return nil
}

func Ldrt(w *bytes.Buffer, cond Condition, rn Reg, rd Reg, offsetMode OffsetMode) error {
	if err := write32(w, uint32(((((70254592 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)) | (uint32(offsetMode) << 23)))); err != nil {
		return err
	}
	return nil
}

func Cdp(w *bytes.Buffer, cond Condition, cpnum Coprocessor) error {
	if err := write32(w, uint32(((234881024 | uint32(cond)) | (uint32(cpnum) << 8)))); err != nil {
		return err
	}
	return nil
}

func Mcr(w *bytes.Buffer, cond Condition, rd Reg, cpnum Coprocessor) error {
	if err := write32(w, uint32((((234881040 | uint32(cond)) | (uint32(rd) << 12)) | (uint32(cpnum) << 8)))); err != nil {
		return err
	}
	return nil
}

func Mrc(w *bytes.Buffer, cond Condition, rd Reg, cpnum Coprocessor) error {
	if err := write32(w, uint32((((235929616 | uint32(cond)) | (uint32(rd) << 12)) | (uint32(cpnum) << 8)))); err != nil {
		return err
	}
	return nil
}

func Mcrr(w *bytes.Buffer, cond Condition, rn Reg, rd Reg, cpnum Coprocessor) error {
	if err := write32(w, uint32(((((205520896 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)) | (uint32(cpnum) << 8)))); err != nil {
		return err
	}
	return nil
}

func Mla(w *bytes.Buffer, cond Condition, updateCprs bool, rn Reg, rd Reg, updateCondition bool) error {
	var updateCprs_ uint32 = 0
	if updateCprs {
		updateCprs_ = 1
	}
	var updateCondition_ uint32 = 0
	if updateCondition {
		updateCondition_ = 1
	}
	if err := write32(w, uint32((((((2097296 | uint32(cond)) | (updateCprs_ << 20)) | (uint32(rn) << 12)) | (uint32(rd) << 16)) | (updateCondition_ << 20)))); err != nil {
		return err
	}
	return nil
}

func Mov(w *bytes.Buffer, cond Condition, updateCprs bool, rd Reg, updateCondition bool) error {
	var updateCprs_ uint32 = 0
	if updateCprs {
		updateCprs_ = 1
	}
	var updateCondition_ uint32 = 0
	if updateCondition {
		updateCondition_ = 1
	}
	if err := write32(w, uint32(((((27262976 | uint32(cond)) | (updateCprs_ << 20)) | (uint32(rd) << 12)) | (updateCondition_ << 20)))); err != nil {
		return err
	}
	return nil
}

func Mrrc(w *bytes.Buffer, cond Condition, rn Reg, rd Reg, cpnum Coprocessor) error {
	if err := write32(w, uint32(((((206569472 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)) | (uint32(cpnum) << 8)))); err != nil {
		return err
	}
	return nil
}

func Mrs(w *bytes.Buffer, cond Condition, rd Reg) error {
	if err := write32(w, uint32(((17760256 | uint32(cond)) | (uint32(rd) << 12)))); err != nil {
		return err
	}
	return nil
}

func Mul(w *bytes.Buffer, cond Condition, updateCprs bool, rd Reg, updateCondition bool) error {
	var updateCprs_ uint32 = 0
	if updateCprs {
		updateCprs_ = 1
	}
	var updateCondition_ uint32 = 0
	if updateCondition {
		updateCondition_ = 1
	}
	if err := write32(w, uint32(((((144 | uint32(cond)) | (updateCprs_ << 20)) | (uint32(rd) << 16)) | (updateCondition_ << 20)))); err != nil {
		return err
	}
	return nil
}

func Mvn(w *bytes.Buffer, cond Condition, updateCprs bool, rd Reg, updateCondition bool) error {
	var updateCprs_ uint32 = 0
	if updateCprs {
		updateCprs_ = 1
	}
	var updateCondition_ uint32 = 0
	if updateCondition {
		updateCondition_ = 1
	}
	if err := write32(w, uint32(((((31457280 | uint32(cond)) | (updateCprs_ << 20)) | (uint32(rd) << 12)) | (updateCondition_ << 20)))); err != nil {
		return err
	}
	return nil
}

func MsrImm(w *bytes.Buffer, cond Condition, fieldmask FieldMask) error {
	if err := write32(w, uint32(((52490240 | uint32(cond)) | (uint32(fieldmask) << 16)))); err != nil {
		return err
	}
	return nil
}

func MsrReg(w *bytes.Buffer, cond Condition, fieldmask FieldMask) error {
	if err := write32(w, uint32(((18935808 | uint32(cond)) | (uint32(fieldmask) << 16)))); err != nil {
		return err
	}
	return nil
}

func Pkhbt(w *bytes.Buffer, cond Condition, rn Reg, rd Reg) error {
	if err := write32(w, uint32((((109051920 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)))); err != nil {
		return err
	}
	return nil
}

func Pkhtb(w *bytes.Buffer, cond Condition, rn Reg, rd Reg) error {
	if err := write32(w, uint32((((109051984 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)))); err != nil {
		return err
	}
	return nil
}

func Pld(w *bytes.Buffer, rn Reg, offsetMode OffsetMode) error {
	if err := write32(w, uint32(((4115722240 | (uint32(rn) << 16)) | (uint32(offsetMode) << 23)))); err != nil {
		return err
	}
	return nil
}

func Qadd(w *bytes.Buffer, cond Condition, rn Reg, rd Reg) error {
	if err := write32(w, uint32((((16777296 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)))); err != nil {
		return err
	}
	return nil
}

func Qadd16(w *bytes.Buffer, cond Condition, rn Reg, rd Reg) error {
	if err := write32(w, uint32((((102764304 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)))); err != nil {
		return err
	}
	return nil
}

func Qadd8(w *bytes.Buffer, cond Condition, rn Reg, rd Reg) error {
	if err := write32(w, uint32((((102764432 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)))); err != nil {
		return err
	}
	return nil
}

func Qaddsubx(w *bytes.Buffer, cond Condition, rn Reg, rd Reg) error {
	if err := write32(w, uint32((((102764336 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)))); err != nil {
		return err
	}
	return nil
}

func Qdadd(w *bytes.Buffer, cond Condition, rn Reg, rd Reg) error {
	if err := write32(w, uint32((((20971600 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)))); err != nil {
		return err
	}
	return nil
}

func Qdsub(w *bytes.Buffer, cond Condition, rn Reg, rd Reg) error {
	if err := write32(w, uint32((((23068752 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)))); err != nil {
		return err
	}
	return nil
}

func Qsub(w *bytes.Buffer, cond Condition, rn Reg, rd Reg) error {
	if err := write32(w, uint32((((18874448 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)))); err != nil {
		return err
	}
	return nil
}

func Qsub16(w *bytes.Buffer, cond Condition, rn Reg, rd Reg) error {
	if err := write32(w, uint32((((102764400 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)))); err != nil {
		return err
	}
	return nil
}

func Qsub8(w *bytes.Buffer, cond Condition, rn Reg, rd Reg) error {
	if err := write32(w, uint32((((102764528 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)))); err != nil {
		return err
	}
	return nil
}

func Qsubaddx(w *bytes.Buffer, cond Condition, rn Reg, rd Reg) error {
	if err := write32(w, uint32((((102764368 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)))); err != nil {
		return err
	}
	return nil
}

func Rev(w *bytes.Buffer, cond Condition, rd Reg) error {
	if err := write32(w, uint32(((113184560 | uint32(cond)) | (uint32(rd) << 12)))); err != nil {
		return err
	}
	return nil
}

func Rev16(w *bytes.Buffer, cond Condition, rd Reg) error {
	if err := write32(w, uint32(((113184688 | uint32(cond)) | (uint32(rd) << 12)))); err != nil {
		return err
	}
	return nil
}

func Revsh(w *bytes.Buffer, cond Condition, rd Reg) error {
	if err := write32(w, uint32(((117378992 | uint32(cond)) | (uint32(rd) << 12)))); err != nil {
		return err
	}
	return nil
}

func Rfe(w *bytes.Buffer, write bool, rn Reg, offsetMode OffsetMode, addressingMode Addressing) error {
	var write_ uint32 = 0
	if write {
		write_ = 1
	}
	if err := write32(w, uint32(((((4161800704 | (write_ << 21)) | (uint32(rn) << 16)) | (uint32(addressingMode) << 23)) | (uint32(offsetMode) << 11)))); err != nil {
		return err
	}
	return nil
}

func Sadd16(w *bytes.Buffer, cond Condition, rn Reg, rd Reg) error {
	if err := write32(w, uint32((((101715728 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)))); err != nil {
		return err
	}
	return nil
}

func Sadd8(w *bytes.Buffer, cond Condition, rn Reg, rd Reg) error {
	if err := write32(w, uint32((((101715856 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)))); err != nil {
		return err
	}
	return nil
}

func Saddsubx(w *bytes.Buffer, cond Condition, rn Reg, rd Reg) error {
	if err := write32(w, uint32((((101715760 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)))); err != nil {
		return err
	}
	return nil
}

func Sel(w *bytes.Buffer, cond Condition, rn Reg, rd Reg) error {
	if err := write32(w, uint32((((109055920 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)))); err != nil {
		return err
	}
	return nil
}

func Setendbe(w *bytes.Buffer) error {
	if err := write32(w, uint32(4043375104)); err != nil {
		return err
	}
	return nil
}

func Setendle(w *bytes.Buffer) error {
	if err := write32(w, uint32(4043374592)); err != nil {
		return err
	}
	return nil
}

func Shadd16(w *bytes.Buffer, cond Condition, rn Reg, rd Reg) error {
	if err := write32(w, uint32((((103812880 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)))); err != nil {
		return err
	}
	return nil
}

func Shadd8(w *bytes.Buffer, cond Condition, rn Reg, rd Reg) error {
	if err := write32(w, uint32((((103813008 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)))); err != nil {
		return err
	}
	return nil
}

func Shaddsubx(w *bytes.Buffer, cond Condition, rn Reg, rd Reg) error {
	if err := write32(w, uint32((((103812912 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)))); err != nil {
		return err
	}
	return nil
}

func Shsub16(w *bytes.Buffer, cond Condition, rn Reg, rd Reg) error {
	if err := write32(w, uint32((((103812976 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)))); err != nil {
		return err
	}
	return nil
}

func Shsub8(w *bytes.Buffer, cond Condition, rn Reg, rd Reg) error {
	if err := write32(w, uint32((((103813104 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)))); err != nil {
		return err
	}
	return nil
}

func Shsubaddx(w *bytes.Buffer, cond Condition, rn Reg, rd Reg) error {
	if err := write32(w, uint32((((103812944 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)))); err != nil {
		return err
	}
	return nil
}

func Smlabb(w *bytes.Buffer, cond Condition, rn Reg, rd Reg) error {
	if err := write32(w, uint32((((16777344 | uint32(cond)) | (uint32(rn) << 12)) | (uint32(rd) << 16)))); err != nil {
		return err
	}
	return nil
}

func Smlabt(w *bytes.Buffer, cond Condition, rn Reg, rd Reg) error {
	if err := write32(w, uint32((((16777376 | uint32(cond)) | (uint32(rn) << 12)) | (uint32(rd) << 16)))); err != nil {
		return err
	}
	return nil
}

func Smlatb(w *bytes.Buffer, cond Condition, rn Reg, rd Reg) error {
	if err := write32(w, uint32((((16777408 | uint32(cond)) | (uint32(rn) << 12)) | (uint32(rd) << 16)))); err != nil {
		return err
	}
	return nil
}

func Smlatt(w *bytes.Buffer, cond Condition, rn Reg, rd Reg) error {
	if err := write32(w, uint32((((16777440 | uint32(cond)) | (uint32(rn) << 12)) | (uint32(rd) << 16)))); err != nil {
		return err
	}
	return nil
}

func Smlad(w *bytes.Buffer, cond Condition, exchange bool, rn Reg, rd Reg) error {
	var exchange_ uint32 = 0
	if exchange {
		exchange_ = 1
	}
	if err := write32(w, uint32(((((117440528 | uint32(cond)) | (exchange_ << 5)) | (uint32(rn) << 12)) | (uint32(rd) << 16)))); err != nil {
		return err
	}
	return nil
}

func Smlal(w *bytes.Buffer, cond Condition, updateCprs bool, updateCondition bool) error {
	var updateCprs_ uint32 = 0
	if updateCprs {
		updateCprs_ = 1
	}
	var updateCondition_ uint32 = 0
	if updateCondition {
		updateCondition_ = 1
	}
	if err := write32(w, uint32((((14680208 | uint32(cond)) | (updateCprs_ << 20)) | (updateCondition_ << 20)))); err != nil {
		return err
	}
	return nil
}

func Smlalbb(w *bytes.Buffer, cond Condition) error {
	if err := write32(w, uint32((20971648 | uint32(cond)))); err != nil {
		return err
	}
	return nil
}

func Smlalbt(w *bytes.Buffer, cond Condition) error {
	if err := write32(w, uint32((20971680 | uint32(cond)))); err != nil {
		return err
	}
	return nil
}

func Smlaltb(w *bytes.Buffer, cond Condition) error {
	if err := write32(w, uint32((20971712 | uint32(cond)))); err != nil {
		return err
	}
	return nil
}

func Smlaltt(w *bytes.Buffer, cond Condition) error {
	if err := write32(w, uint32((20971744 | uint32(cond)))); err != nil {
		return err
	}
	return nil
}

func Smlald(w *bytes.Buffer, cond Condition, exchange bool) error {
	var exchange_ uint32 = 0
	if exchange {
		exchange_ = 1
	}
	if err := write32(w, uint32(((121634832 | uint32(cond)) | (exchange_ << 5)))); err != nil {
		return err
	}
	return nil
}

func Smlawb(w *bytes.Buffer, cond Condition, rn Reg, rd Reg) error {
	if err := write32(w, uint32((((18874496 | uint32(cond)) | (uint32(rn) << 12)) | (uint32(rd) << 16)))); err != nil {
		return err
	}
	return nil
}

func Smlawt(w *bytes.Buffer, cond Condition, rn Reg, rd Reg) error {
	if err := write32(w, uint32((((18874560 | uint32(cond)) | (uint32(rn) << 12)) | (uint32(rd) << 16)))); err != nil {
		return err
	}
	return nil
}

func Smlsd(w *bytes.Buffer, cond Condition, exchange bool, rn Reg, rd Reg) error {
	var exchange_ uint32 = 0
	if exchange {
		exchange_ = 1
	}
	if err := write32(w, uint32(((((117440592 | uint32(cond)) | (exchange_ << 5)) | (uint32(rn) << 12)) | (uint32(rd) << 16)))); err != nil {
		return err
	}
	return nil
}

func Smlsld(w *bytes.Buffer, cond Condition, exchange bool) error {
	var exchange_ uint32 = 0
	if exchange {
		exchange_ = 1
	}
	if err := write32(w, uint32(((121634896 | uint32(cond)) | (exchange_ << 5)))); err != nil {
		return err
	}
	return nil
}

func Smmla(w *bytes.Buffer, cond Condition, rn Reg, rd Reg) error {
	if err := write32(w, uint32((((122683408 | uint32(cond)) | (uint32(rn) << 12)) | (uint32(rd) << 16)))); err != nil {
		return err
	}
	return nil
}

func Smmls(w *bytes.Buffer, cond Condition, rn Reg, rd Reg) error {
	if err := write32(w, uint32((((122683600 | uint32(cond)) | (uint32(rn) << 12)) | (uint32(rd) << 16)))); err != nil {
		return err
	}
	return nil
}

func Smmul(w *bytes.Buffer, cond Condition, rd Reg) error {
	if err := write32(w, uint32(((122744848 | uint32(cond)) | (uint32(rd) << 16)))); err != nil {
		return err
	}
	return nil
}

func Smuad(w *bytes.Buffer, cond Condition, exchange bool, rd Reg) error {
	var exchange_ uint32 = 0
	if exchange {
		exchange_ = 1
	}
	if err := write32(w, uint32((((117501968 | uint32(cond)) | (exchange_ << 5)) | (uint32(rd) << 16)))); err != nil {
		return err
	}
	return nil
}

func Smulbb(w *bytes.Buffer, cond Condition, rd Reg) error {
	if err := write32(w, uint32(((23068800 | uint32(cond)) | (uint32(rd) << 16)))); err != nil {
		return err
	}
	return nil
}

func Smulbt(w *bytes.Buffer, cond Condition, rd Reg) error {
	if err := write32(w, uint32(((23068832 | uint32(cond)) | (uint32(rd) << 16)))); err != nil {
		return err
	}
	return nil
}

func Smultb(w *bytes.Buffer, cond Condition, rd Reg) error {
	if err := write32(w, uint32(((23068864 | uint32(cond)) | (uint32(rd) << 16)))); err != nil {
		return err
	}
	return nil
}

func Smultt(w *bytes.Buffer, cond Condition, rd Reg) error {
	if err := write32(w, uint32(((23068896 | uint32(cond)) | (uint32(rd) << 16)))); err != nil {
		return err
	}
	return nil
}

func Smull(w *bytes.Buffer, cond Condition, updateCprs bool, updateCondition bool) error {
	var updateCprs_ uint32 = 0
	if updateCprs {
		updateCprs_ = 1
	}
	var updateCondition_ uint32 = 0
	if updateCondition {
		updateCondition_ = 1
	}
	if err := write32(w, uint32((((12583056 | uint32(cond)) | (updateCprs_ << 20)) | (updateCondition_ << 20)))); err != nil {
		return err
	}
	return nil
}

func Smulwb(w *bytes.Buffer, cond Condition, rd Reg) error {
	if err := write32(w, uint32(((18874528 | uint32(cond)) | (uint32(rd) << 16)))); err != nil {
		return err
	}
	return nil
}

func Smulwt(w *bytes.Buffer, cond Condition, rd Reg) error {
	if err := write32(w, uint32(((18874592 | uint32(cond)) | (uint32(rd) << 16)))); err != nil {
		return err
	}
	return nil
}

func Smusd(w *bytes.Buffer, cond Condition, exchange bool, rd Reg) error {
	var exchange_ uint32 = 0
	if exchange {
		exchange_ = 1
	}
	if err := write32(w, uint32((((117502032 | uint32(cond)) | (exchange_ << 5)) | (uint32(rd) << 16)))); err != nil {
		return err
	}
	return nil
}

func Srs(w *bytes.Buffer, write bool, mode Mode, offsetMode OffsetMode, addressingMode Addressing) error {
	var write_ uint32 = 0
	if write {
		write_ = 1
	}
	if err := write32(w, uint32(((((4165797120 | (write_ << 21)) | (uint32(mode) << 0)) | (uint32(addressingMode) << 23)) | (uint32(offsetMode) << 11)))); err != nil {
		return err
	}
	return nil
}

func Ssat(w *bytes.Buffer, cond Condition, rd Reg) error {
	if err := write32(w, uint32(((105906192 | uint32(cond)) | (uint32(rd) << 12)))); err != nil {
		return err
	}
	return nil
}

func Ssat16(w *bytes.Buffer, cond Condition, rd Reg) error {
	if err := write32(w, uint32(((111152944 | uint32(cond)) | (uint32(rd) << 12)))); err != nil {
		return err
	}
	return nil
}

func Ssub16(w *bytes.Buffer, cond Condition, rn Reg, rd Reg) error {
	if err := write32(w, uint32((((101715824 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)))); err != nil {
		return err
	}
	return nil
}

func Ssub8(w *bytes.Buffer, cond Condition, rn Reg, rd Reg) error {
	if err := write32(w, uint32((((101715952 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)))); err != nil {
		return err
	}
	return nil
}

func Ssubaddx(w *bytes.Buffer, cond Condition, rn Reg, rd Reg) error {
	if err := write32(w, uint32((((101715792 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)))); err != nil {
		return err
	}
	return nil
}

func Stc(w *bytes.Buffer, cond Condition, write bool, rn Reg, cpnum Coprocessor, offsetMode OffsetMode, addressingMode Addressing) error {
	var write_ uint32 = 0
	if write {
		write_ = 1
	}
	if err := write32(w, uint32(((((((201326592 | uint32(cond)) | (write_ << 21)) | (uint32(rn) << 16)) | (uint32(cpnum) << 8)) | (uint32(addressingMode) << 23)) | (uint32(offsetMode) << 11)))); err != nil {
		return err
	}
	return nil
}

func Stm(w *bytes.Buffer, cond Condition, rn Reg, offsetMode OffsetMode, addressingMode Addressing, registers RegList, write bool, userMode bool) error {
	var write_ uint32 = 0
	if write {
		write_ = 1
	}
	var userMode_ uint32 = 0
	if userMode {
		userMode_ = 1
	}
	if !((userMode_ == 0) || (write_ == 0)) {
		return errors.New("Failed precondition: ((userMode_ == 0) || (write_ == 0)).")
	}
	if err := write32(w, uint32(((((((((134217728 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(addressingMode) << 23)) | (uint32(offsetMode) << 11)) | (uint32(addressingMode) << 23)) | uint32(registers)) | (userMode_ << 21)) | (write_ << 10)))); err != nil {
		return err
	}
	return nil
}

func Str(w *bytes.Buffer, cond Condition, write bool, rn Reg, rd Reg, offsetMode OffsetMode, addressingMode Addressing) error {
	var write_ uint32 = 0
	if write {
		write_ = 1
	}
	if err := write32(w, uint32(((((((67108864 | uint32(cond)) | (write_ << 21)) | (uint32(rn) << 16)) | (uint32(rd) << 12)) | (uint32(addressingMode) << 23)) | (uint32(offsetMode) << 11)))); err != nil {
		return err
	}
	return nil
}

func Strb(w *bytes.Buffer, cond Condition, write bool, rn Reg, rd Reg, offsetMode OffsetMode, addressingMode Addressing) error {
	var write_ uint32 = 0
	if write {
		write_ = 1
	}
	if err := write32(w, uint32(((((((71303168 | uint32(cond)) | (write_ << 21)) | (uint32(rn) << 16)) | (uint32(rd) << 12)) | (uint32(addressingMode) << 23)) | (uint32(offsetMode) << 11)))); err != nil {
		return err
	}
	return nil
}

func Strbt(w *bytes.Buffer, cond Condition, rn Reg, rd Reg, offsetMode OffsetMode) error {
	if err := write32(w, uint32(((((73400320 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)) | (uint32(offsetMode) << 23)))); err != nil {
		return err
	}
	return nil
}

func Strd(w *bytes.Buffer, cond Condition, write bool, rn Reg, rd Reg, offsetMode OffsetMode, addressingMode Addressing) error {
	var write_ uint32 = 0
	if write {
		write_ = 1
	}
	if err := write32(w, uint32(((((((240 | uint32(cond)) | (write_ << 21)) | (uint32(rn) << 16)) | (uint32(rd) << 12)) | (uint32(addressingMode) << 23)) | (uint32(offsetMode) << 11)))); err != nil {
		return err
	}
	return nil
}

func Strex(w *bytes.Buffer, cond Condition, rn Reg, rd Reg) error {
	if err := write32(w, uint32((((25169808 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)))); err != nil {
		return err
	}
	return nil
}

func Strh(w *bytes.Buffer, cond Condition, write bool, rn Reg, rd Reg, offsetMode OffsetMode, addressingMode Addressing) error {
	var write_ uint32 = 0
	if write {
		write_ = 1
	}
	if err := write32(w, uint32(((((((176 | uint32(cond)) | (write_ << 21)) | (uint32(rn) << 16)) | (uint32(rd) << 12)) | (uint32(addressingMode) << 23)) | (uint32(offsetMode) << 11)))); err != nil {
		return err
	}
	return nil
}

func Strt(w *bytes.Buffer, cond Condition, rn Reg, rd Reg, offsetMode OffsetMode) error {
	if err := write32(w, uint32(((((69206016 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)) | (uint32(offsetMode) << 23)))); err != nil {
		return err
	}
	return nil
}

func Swi(w *bytes.Buffer, cond Condition) error {
	if err := write32(w, uint32((251658240 | uint32(cond)))); err != nil {
		return err
	}
	return nil
}

func Swp(w *bytes.Buffer, cond Condition, rn Reg, rd Reg) error {
	if err := write32(w, uint32((((16777360 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)))); err != nil {
		return err
	}
	return nil
}

func Swpb(w *bytes.Buffer, cond Condition, rn Reg, rd Reg) error {
	if err := write32(w, uint32((((20971664 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)))); err != nil {
		return err
	}
	return nil
}

func Sxtab(w *bytes.Buffer, cond Condition, rn Reg, rd Reg, rotate Rotation) error {
	if err := write32(w, uint32(((((111149168 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)) | (uint32(rotate) << 10)))); err != nil {
		return err
	}
	return nil
}

func Sxtab16(w *bytes.Buffer, cond Condition, rn Reg, rd Reg, rotate Rotation) error {
	if err := write32(w, uint32(((((109052016 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)) | (uint32(rotate) << 10)))); err != nil {
		return err
	}
	return nil
}

func Sxtah(w *bytes.Buffer, cond Condition, rn Reg, rd Reg, rotate Rotation) error {
	if err := write32(w, uint32(((((112197744 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)) | (uint32(rotate) << 10)))); err != nil {
		return err
	}
	return nil
}

func Sxtb(w *bytes.Buffer, cond Condition, rd Reg, rotate Rotation) error {
	if err := write32(w, uint32((((112132208 | uint32(cond)) | (uint32(rd) << 12)) | (uint32(rotate) << 10)))); err != nil {
		return err
	}
	return nil
}

func Sxtb16(w *bytes.Buffer, cond Condition, rd Reg, rotate Rotation) error {
	if err := write32(w, uint32((((110035056 | uint32(cond)) | (uint32(rd) << 12)) | (uint32(rotate) << 10)))); err != nil {
		return err
	}
	return nil
}

func Sxth(w *bytes.Buffer, cond Condition, rd Reg, rotate Rotation) error {
	if err := write32(w, uint32((((113180784 | uint32(cond)) | (uint32(rd) << 12)) | (uint32(rotate) << 10)))); err != nil {
		return err
	}
	return nil
}

func Teq(w *bytes.Buffer, cond Condition, rn Reg) error {
	if err := write32(w, uint32(((19922944 | uint32(cond)) | (uint32(rn) << 16)))); err != nil {
		return err
	}
	return nil
}

func Tst(w *bytes.Buffer, cond Condition, rn Reg) error {
	if err := write32(w, uint32(((17825792 | uint32(cond)) | (uint32(rn) << 16)))); err != nil {
		return err
	}
	return nil
}

func Uadd16(w *bytes.Buffer, cond Condition, rn Reg, rd Reg) error {
	if err := write32(w, uint32((((105910032 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)))); err != nil {
		return err
	}
	return nil
}

func Uadd8(w *bytes.Buffer, cond Condition, rn Reg, rd Reg) error {
	if err := write32(w, uint32((((105910160 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)))); err != nil {
		return err
	}
	return nil
}

func Uaddsubx(w *bytes.Buffer, cond Condition, rn Reg, rd Reg) error {
	if err := write32(w, uint32((((105910064 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)))); err != nil {
		return err
	}
	return nil
}

func Uhadd16(w *bytes.Buffer, cond Condition, rn Reg, rd Reg) error {
	if err := write32(w, uint32((((108007184 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)))); err != nil {
		return err
	}
	return nil
}

func Uhadd8(w *bytes.Buffer, cond Condition, rn Reg, rd Reg) error {
	if err := write32(w, uint32((((108007312 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)))); err != nil {
		return err
	}
	return nil
}

func Uhaddsubx(w *bytes.Buffer, cond Condition, rn Reg, rd Reg) error {
	if err := write32(w, uint32((((108007216 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)))); err != nil {
		return err
	}
	return nil
}

func Uhsub16(w *bytes.Buffer, cond Condition, rn Reg, rd Reg) error {
	if err := write32(w, uint32((((108007280 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)))); err != nil {
		return err
	}
	return nil
}

func Uhsub8(w *bytes.Buffer, cond Condition, rn Reg, rd Reg) error {
	if err := write32(w, uint32((((108007408 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)))); err != nil {
		return err
	}
	return nil
}

func Uhsubaddx(w *bytes.Buffer, cond Condition, rn Reg, rd Reg) error {
	if err := write32(w, uint32((((108007248 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)))); err != nil {
		return err
	}
	return nil
}

func Umaal(w *bytes.Buffer, cond Condition) error {
	if err := write32(w, uint32((4194448 | uint32(cond)))); err != nil {
		return err
	}
	return nil
}

func Umlal(w *bytes.Buffer, cond Condition, updateCprs bool, updateCondition bool) error {
	var updateCprs_ uint32 = 0
	if updateCprs {
		updateCprs_ = 1
	}
	var updateCondition_ uint32 = 0
	if updateCondition {
		updateCondition_ = 1
	}
	if err := write32(w, uint32((((10485904 | uint32(cond)) | (updateCprs_ << 20)) | (updateCondition_ << 20)))); err != nil {
		return err
	}
	return nil
}

func Umull(w *bytes.Buffer, cond Condition, updateCprs bool, updateCondition bool) error {
	var updateCprs_ uint32 = 0
	if updateCprs {
		updateCprs_ = 1
	}
	var updateCondition_ uint32 = 0
	if updateCondition {
		updateCondition_ = 1
	}
	if err := write32(w, uint32((((8388752 | uint32(cond)) | (updateCprs_ << 20)) | (updateCondition_ << 20)))); err != nil {
		return err
	}
	return nil
}

func Uqadd16(w *bytes.Buffer, cond Condition, rn Reg, rd Reg) error {
	if err := write32(w, uint32((((106958608 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)))); err != nil {
		return err
	}
	return nil
}

func Uqadd8(w *bytes.Buffer, cond Condition, rn Reg, rd Reg) error {
	if err := write32(w, uint32((((106958736 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)))); err != nil {
		return err
	}
	return nil
}

func Uqaddsubx(w *bytes.Buffer, cond Condition, rn Reg, rd Reg) error {
	if err := write32(w, uint32((((106958640 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)))); err != nil {
		return err
	}
	return nil
}

func Uqsub16(w *bytes.Buffer, cond Condition, rn Reg, rd Reg) error {
	if err := write32(w, uint32((((106958704 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)))); err != nil {
		return err
	}
	return nil
}

func Uqsub8(w *bytes.Buffer, cond Condition, rn Reg, rd Reg) error {
	if err := write32(w, uint32((((106958832 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)))); err != nil {
		return err
	}
	return nil
}

func Uqsubaddx(w *bytes.Buffer, cond Condition, rn Reg, rd Reg) error {
	if err := write32(w, uint32((((106958672 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)))); err != nil {
		return err
	}
	return nil
}

func Usad8(w *bytes.Buffer, cond Condition, rd Reg) error {
	if err := write32(w, uint32(((125890576 | uint32(cond)) | (uint32(rd) << 16)))); err != nil {
		return err
	}
	return nil
}

func Usada8(w *bytes.Buffer, cond Condition, rn Reg, rd Reg) error {
	if err := write32(w, uint32((((125829136 | uint32(cond)) | (uint32(rn) << 12)) | (uint32(rd) << 16)))); err != nil {
		return err
	}
	return nil
}

func Usat(w *bytes.Buffer, cond Condition, rd Reg) error {
	if err := write32(w, uint32(((115343376 | uint32(cond)) | (uint32(rd) << 12)))); err != nil {
		return err
	}
	return nil
}

func Usat16(w *bytes.Buffer, cond Condition, rd Reg) error {
	if err := write32(w, uint32(((115347248 | uint32(cond)) | (uint32(rd) << 12)))); err != nil {
		return err
	}
	return nil
}

func Usub16(w *bytes.Buffer, cond Condition, rn Reg, rd Reg) error {
	if err := write32(w, uint32((((105910128 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)))); err != nil {
		return err
	}
	return nil
}

func Usub8(w *bytes.Buffer, cond Condition, rn Reg, rd Reg) error {
	if err := write32(w, uint32((((105910256 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)))); err != nil {
		return err
	}
	return nil
}

func Usubaddx(w *bytes.Buffer, cond Condition, rn Reg, rd Reg) error {
	if err := write32(w, uint32((((105910096 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)))); err != nil {
		return err
	}
	return nil
}

func Uxtab(w *bytes.Buffer, cond Condition, rn Reg, rd Reg, rotate Rotation) error {
	if err := write32(w, uint32(((((115343472 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)) | (uint32(rotate) << 10)))); err != nil {
		return err
	}
	return nil
}

func Uxtab16(w *bytes.Buffer, cond Condition, rn Reg, rd Reg, rotate Rotation) error {
	if err := write32(w, uint32(((((113246320 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)) | (uint32(rotate) << 10)))); err != nil {
		return err
	}
	return nil
}

func Uxtah(w *bytes.Buffer, cond Condition, rn Reg, rd Reg, rotate Rotation) error {
	if err := write32(w, uint32(((((116392048 | uint32(cond)) | (uint32(rn) << 16)) | (uint32(rd) << 12)) | (uint32(rotate) << 10)))); err != nil {
		return err
	}
	return nil
}

func Uxtb(w *bytes.Buffer, cond Condition, rd Reg, rotate Rotation) error {
	if err := write32(w, uint32((((116326512 | uint32(cond)) | (uint32(rd) << 12)) | (uint32(rotate) << 10)))); err != nil {
		return err
	}
	return nil
}

func Uxtb16(w *bytes.Buffer, cond Condition, rd Reg, rotate Rotation) error {
	if err := write32(w, uint32((((114229360 | uint32(cond)) | (uint32(rd) << 12)) | (uint32(rotate) << 10)))); err != nil {
		return err
	}
	return nil
}

func Uxth(w *bytes.Buffer, cond Condition, rd Reg, rotate Rotation) error {
	if err := write32(w, uint32((((117375088 | uint32(cond)) | (uint32(rd) << 12)) | (uint32(rotate) << 10)))); err != nil {
		return err
	}
	return nil
}

