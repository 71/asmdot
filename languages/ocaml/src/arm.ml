open Core

(** An ARM register. *)
type Reg = uint8
module Reg
  let r0 = Reg 0 ;;
  let r1 = Reg 1 ;;
  let r2 = Reg 2 ;;
  let r3 = Reg 3 ;;
  let r4 = Reg 4 ;;
  let r5 = Reg 5 ;;
  let r6 = Reg 6 ;;
  let r7 = Reg 7 ;;
  let r8 = Reg 8 ;;
  let r9 = Reg 9 ;;
  let r10 = Reg 10 ;;
  let r11 = Reg 11 ;;
  let r12 = Reg 12 ;;
  let r13 = Reg 13 ;;
  let r14 = Reg 14 ;;
  let r15 = Reg 15 ;;
  let a1 = Reg 0 ;;
  let a2 = Reg 1 ;;
  let a3 = Reg 2 ;;
  let a4 = Reg 3 ;;
  let v1 = Reg 4 ;;
  let v2 = Reg 5 ;;
  let v3 = Reg 6 ;;
  let v4 = Reg 7 ;;
  let v5 = Reg 8 ;;
  let v6 = Reg 9 ;;
  let v7 = Reg 10 ;;
  let v8 = Reg 11 ;;
  let ip = Reg 12 ;;
  let sp = Reg 13 ;;
  let lr = Reg 14 ;;
  let pc = Reg 15 ;;
  let wr = Reg 7 ;;
  let sb = Reg 9 ;;
  let sl = Reg 10 ;;
  let fp = Reg 11 ;;
;;

(** A list of ARM registers, where each register corresponds to a single bit. *)
type RegList =
  | R0
  | R1
  | R2
  | R3
  | R4
  | R5
  | R6
  | R7
  | R8
  | R9
  | R10
  | R11
  | R12
  | R13
  | R14
  | R15
  | A1
  | A2
  | A3
  | A4
  | V1
  | V2
  | V3
  | V4
  | V5
  | V6
  | V7
  | V8
  | IP
  | SP
  | LR
  | PC
  | WR
  | SB
  | SL
  | FP

(** An ARM coprocessor. *)
type Coprocessor = uint8
module Coprocessor
  let cp0 = Coprocessor 0 ;;
  let cp1 = Coprocessor 1 ;;
  let cp2 = Coprocessor 2 ;;
  let cp3 = Coprocessor 3 ;;
  let cp4 = Coprocessor 4 ;;
  let cp5 = Coprocessor 5 ;;
  let cp6 = Coprocessor 6 ;;
  let cp7 = Coprocessor 7 ;;
  let cp8 = Coprocessor 8 ;;
  let cp9 = Coprocessor 9 ;;
  let cp10 = Coprocessor 10 ;;
  let cp11 = Coprocessor 11 ;;
  let cp12 = Coprocessor 12 ;;
  let cp13 = Coprocessor 13 ;;
  let cp14 = Coprocessor 14 ;;
  let cp15 = Coprocessor 15 ;;
;;

(** Condition for an ARM instruction to be executed. *)
type Condition =
  | EQ
  | NE
  | HS
  | LO
  | MI
  | PL
  | VS
  | VC
  | HI
  | LS
  | GE
  | LT
  | GT
  | LE
  | AL
  | UN
  | CS
  | CC

(** Processor mode. *)
type Mode =
  | USR
  | FIQ
  | IRQ
  | SVC
  | ABT
  | UND
  | SYS

(** Kind of a shift. *)
type Shift =
  | LSL
  | LSR
  | ASR
  | ROR
  | RRX

(** Kind of a right rotation. *)
type Rotation =
  | NOP
  | ROR8
  | ROR16
  | ROR24

(** Field mask bits. *)
type FieldMask =
  | C
  | X
  | S
  | F

(** Interrupt flags. *)
type InterruptFlags =
  | F
  | I
  | A

(** Addressing type. *)
type Addressing =
  | PostIndexed
  | PreIndexed
  | Offset

(** Offset adding or subtracting mode. *)
type OffsetMode =
  | Subtract
  | Add


(** Emits an 'adc' instruction. *)
val adc : (_, _) t -> Condition -> bool -> Reg -> Reg -> bool -> unit
let adc buf cond update_cprs rn rd update_condition =
  Iobuf.Poke.uint32_le buf (((((10485760 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20));
  Iobuf.advance buf 4
;;

(** Emits an 'add' instruction. *)
val add : (_, _) t -> Condition -> bool -> Reg -> Reg -> bool -> unit
let add buf cond update_cprs rn rd update_condition =
  Iobuf.Poke.uint32_le buf (((((8388608 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20));
  Iobuf.advance buf 4
;;

(** Emits an 'and' instruction. *)
val and : (_, _) t -> Condition -> bool -> Reg -> Reg -> bool -> unit
let and buf cond update_cprs rn rd update_condition =
  Iobuf.Poke.uint32_le buf (((((0 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20));
  Iobuf.advance buf 4
;;

(** Emits an 'eor' instruction. *)
val eor : (_, _) t -> Condition -> bool -> Reg -> Reg -> bool -> unit
let eor buf cond update_cprs rn rd update_condition =
  Iobuf.Poke.uint32_le buf (((((2097152 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20));
  Iobuf.advance buf 4
;;

(** Emits an 'orr' instruction. *)
val orr : (_, _) t -> Condition -> bool -> Reg -> Reg -> bool -> unit
let orr buf cond update_cprs rn rd update_condition =
  Iobuf.Poke.uint32_le buf (((((25165824 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20));
  Iobuf.advance buf 4
;;

(** Emits a 'rsb' instruction. *)
val rsb : (_, _) t -> Condition -> bool -> Reg -> Reg -> bool -> unit
let rsb buf cond update_cprs rn rd update_condition =
  Iobuf.Poke.uint32_le buf (((((6291456 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20));
  Iobuf.advance buf 4
;;

(** Emits a 'rsc' instruction. *)
val rsc : (_, _) t -> Condition -> bool -> Reg -> Reg -> bool -> unit
let rsc buf cond update_cprs rn rd update_condition =
  Iobuf.Poke.uint32_le buf (((((14680064 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20));
  Iobuf.advance buf 4
;;

(** Emits a 'sbc' instruction. *)
val sbc : (_, _) t -> Condition -> bool -> Reg -> Reg -> bool -> unit
let sbc buf cond update_cprs rn rd update_condition =
  Iobuf.Poke.uint32_le buf (((((12582912 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20));
  Iobuf.advance buf 4
;;

(** Emits a 'sub' instruction. *)
val sub : (_, _) t -> Condition -> bool -> Reg -> Reg -> bool -> unit
let sub buf cond update_cprs rn rd update_condition =
  Iobuf.Poke.uint32_le buf (((((4194304 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20));
  Iobuf.advance buf 4
;;

(** Emits a 'bkpt' instruction. *)
val bkpt : (_, _) t -> uint16 -> unit
let bkpt buf immed =
  Iobuf.Poke.uint32_le buf ((3776970864 | ((immed & 65520) << 8)) | ((immed & 15) << 0));
  Iobuf.advance buf 4
;;

(** Emits a 'b' instruction. *)
val b : (_, _) t -> Condition -> unit
let b buf cond =
  Iobuf.Poke.uint32_le buf (167772160 | cond);
  Iobuf.advance buf 4
;;

(** Emits a 'bic' instruction. *)
val bic : (_, _) t -> Condition -> bool -> Reg -> Reg -> bool -> unit
let bic buf cond update_cprs rn rd update_condition =
  Iobuf.Poke.uint32_le buf (((((29360128 | cond) | (update_cprs << 20)) | (rn << 16)) | (rd << 12)) | (update_condition << 20));
  Iobuf.advance buf 4
;;

(** Emits a 'blx' instruction. *)
val blx : (_, _) t -> Condition -> unit
let blx buf cond =
  Iobuf.Poke.uint32_le buf (19922736 | cond);
  Iobuf.advance buf 4
;;

(** Emits a 'bx' instruction. *)
val bx : (_, _) t -> Condition -> unit
let bx buf cond =
  Iobuf.Poke.uint32_le buf (19922704 | cond);
  Iobuf.advance buf 4
;;

(** Emits a 'bxj' instruction. *)
val bxj : (_, _) t -> Condition -> unit
let bxj buf cond =
  Iobuf.Poke.uint32_le buf (19922720 | cond);
  Iobuf.advance buf 4
;;

(** Emits a 'blxun' instruction. *)
val blxun : (_, _) t -> unit
let blxun buf =
  Iobuf.Poke.uint32_le buf 4194304000;
  Iobuf.advance buf 4
;;

(** Emits a 'clz' instruction. *)
val clz : (_, _) t -> Condition -> Reg -> unit
let clz buf cond rd =
  Iobuf.Poke.uint32_le buf ((24055568 | cond) | (rd << 12));
  Iobuf.advance buf 4
;;

(** Emits a 'cmn' instruction. *)
val cmn : (_, _) t -> Condition -> Reg -> unit
let cmn buf cond rn =
  Iobuf.Poke.uint32_le buf ((24117248 | cond) | (rn << 16));
  Iobuf.advance buf 4
;;

(** Emits a 'cmp' instruction. *)
val cmp : (_, _) t -> Condition -> Reg -> unit
let cmp buf cond rn =
  Iobuf.Poke.uint32_le buf ((22020096 | cond) | (rn << 16));
  Iobuf.advance buf 4
;;

(** Emits a 'cpy' instruction. *)
val cpy : (_, _) t -> Condition -> Reg -> unit
let cpy buf cond rd =
  Iobuf.Poke.uint32_le buf ((27262976 | cond) | (rd << 12));
  Iobuf.advance buf 4
;;

(** Emits a 'cps' instruction. *)
val cps : (_, _) t -> Mode -> unit
let cps buf mode =
  Iobuf.Poke.uint32_le buf (4043440128 | (mode << 0));
  Iobuf.advance buf 4
;;

(** Emits a 'cpsie' instruction. *)
val cpsie : (_, _) t -> InterruptFlags -> unit
let cpsie buf iflags =
  Iobuf.Poke.uint32_le buf (4043833344 | (iflags << 6));
  Iobuf.advance buf 4
;;

(** Emits a 'cpsid' instruction. *)
val cpsid : (_, _) t -> InterruptFlags -> unit
let cpsid buf iflags =
  Iobuf.Poke.uint32_le buf (4044095488 | (iflags << 6));
  Iobuf.advance buf 4
;;

(** Emits a 'cpsie_mode' instruction. *)
val cpsie_mode : (_, _) t -> InterruptFlags -> Mode -> unit
let cpsie_mode buf iflags mode =
  Iobuf.Poke.uint32_le buf ((4043964416 | (iflags << 6)) | (mode << 0));
  Iobuf.advance buf 4
;;

(** Emits a 'cpsid_mode' instruction. *)
val cpsid_mode : (_, _) t -> InterruptFlags -> Mode -> unit
let cpsid_mode buf iflags mode =
  Iobuf.Poke.uint32_le buf ((4044226560 | (iflags << 6)) | (mode << 0));
  Iobuf.advance buf 4
;;

(** Emits a 'ldc' instruction. *)
val ldc : (_, _) t -> Condition -> bool -> Reg -> Coprocessor -> OffsetMode -> Addressing -> unit
let ldc buf cond write rn cpnum offset_mode addressing_mode =
  Iobuf.Poke.uint32_le buf ((((((202375168 | cond) | (write << 21)) | (rn << 16)) | (cpnum << 8)) | (addressing_mode << 23)) | (offset_mode << 11));
  Iobuf.advance buf 4
;;

(** Emits a 'ldm' instruction. *)
val ldm : (_, _) t -> Condition -> Reg -> OffsetMode -> Addressing -> RegList -> bool -> bool -> unit
let ldm buf cond rn offset_mode addressing_mode registers write copy_spsr =
  assert ((copy_spsr == 1) ^ (write == (registers & 32768)));
  Iobuf.Poke.uint32_le buf ((((((((135266304 | cond) | (rn << 16)) | (addressing_mode << 23)) | (offset_mode << 11)) | (addressing_mode << 23)) | registers) | (copy_spsr << 21)) | (write << 10));
  Iobuf.advance buf 4
;;

(** Emits a 'ldr' instruction. *)
val ldr : (_, _) t -> Condition -> bool -> Reg -> Reg -> OffsetMode -> Addressing -> unit
let ldr buf cond write rn rd offset_mode addressing_mode =
  Iobuf.Poke.uint32_le buf ((((((68157440 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11));
  Iobuf.advance buf 4
;;

(** Emits a 'ldrb' instruction. *)
val ldrb : (_, _) t -> Condition -> bool -> Reg -> Reg -> OffsetMode -> Addressing -> unit
let ldrb buf cond write rn rd offset_mode addressing_mode =
  Iobuf.Poke.uint32_le buf ((((((72351744 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11));
  Iobuf.advance buf 4
;;

(** Emits a 'ldrbt' instruction. *)
val ldrbt : (_, _) t -> Condition -> Reg -> Reg -> OffsetMode -> unit
let ldrbt buf cond rn rd offset_mode =
  Iobuf.Poke.uint32_le buf ((((74448896 | cond) | (rn << 16)) | (rd << 12)) | (offset_mode << 23));
  Iobuf.advance buf 4
;;

(** Emits a 'ldrd' instruction. *)
val ldrd : (_, _) t -> Condition -> bool -> Reg -> Reg -> OffsetMode -> Addressing -> unit
let ldrd buf cond write rn rd offset_mode addressing_mode =
  Iobuf.Poke.uint32_le buf ((((((208 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11));
  Iobuf.advance buf 4
;;

(** Emits a 'ldrex' instruction. *)
val ldrex : (_, _) t -> Condition -> Reg -> Reg -> unit
let ldrex buf cond rn rd =
  Iobuf.Poke.uint32_le buf (((26218399 | cond) | (rn << 16)) | (rd << 12));
  Iobuf.advance buf 4
;;

(** Emits a 'ldrh' instruction. *)
val ldrh : (_, _) t -> Condition -> bool -> Reg -> Reg -> OffsetMode -> Addressing -> unit
let ldrh buf cond write rn rd offset_mode addressing_mode =
  Iobuf.Poke.uint32_le buf ((((((1048752 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11));
  Iobuf.advance buf 4
;;

(** Emits a 'ldrsb' instruction. *)
val ldrsb : (_, _) t -> Condition -> bool -> Reg -> Reg -> OffsetMode -> Addressing -> unit
let ldrsb buf cond write rn rd offset_mode addressing_mode =
  Iobuf.Poke.uint32_le buf ((((((1048784 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11));
  Iobuf.advance buf 4
;;

(** Emits a 'ldrsh' instruction. *)
val ldrsh : (_, _) t -> Condition -> bool -> Reg -> Reg -> OffsetMode -> Addressing -> unit
let ldrsh buf cond write rn rd offset_mode addressing_mode =
  Iobuf.Poke.uint32_le buf ((((((1048816 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11));
  Iobuf.advance buf 4
;;

(** Emits a 'ldrt' instruction. *)
val ldrt : (_, _) t -> Condition -> Reg -> Reg -> OffsetMode -> unit
let ldrt buf cond rn rd offset_mode =
  Iobuf.Poke.uint32_le buf ((((70254592 | cond) | (rn << 16)) | (rd << 12)) | (offset_mode << 23));
  Iobuf.advance buf 4
;;

(** Emits a 'cdp' instruction. *)
val cdp : (_, _) t -> Condition -> Coprocessor -> unit
let cdp buf cond cpnum =
  Iobuf.Poke.uint32_le buf ((234881024 | cond) | (cpnum << 8));
  Iobuf.advance buf 4
;;

(** Emits a 'mcr' instruction. *)
val mcr : (_, _) t -> Condition -> Reg -> Coprocessor -> unit
let mcr buf cond rd cpnum =
  Iobuf.Poke.uint32_le buf (((234881040 | cond) | (rd << 12)) | (cpnum << 8));
  Iobuf.advance buf 4
;;

(** Emits a 'mrc' instruction. *)
val mrc : (_, _) t -> Condition -> Reg -> Coprocessor -> unit
let mrc buf cond rd cpnum =
  Iobuf.Poke.uint32_le buf (((235929616 | cond) | (rd << 12)) | (cpnum << 8));
  Iobuf.advance buf 4
;;

(** Emits a 'mcrr' instruction. *)
val mcrr : (_, _) t -> Condition -> Reg -> Reg -> Coprocessor -> unit
let mcrr buf cond rn rd cpnum =
  Iobuf.Poke.uint32_le buf ((((205520896 | cond) | (rn << 16)) | (rd << 12)) | (cpnum << 8));
  Iobuf.advance buf 4
;;

(** Emits a 'mla' instruction. *)
val mla : (_, _) t -> Condition -> bool -> Reg -> Reg -> bool -> unit
let mla buf cond update_cprs rn rd update_condition =
  Iobuf.Poke.uint32_le buf (((((2097296 | cond) | (update_cprs << 20)) | (rn << 12)) | (rd << 16)) | (update_condition << 20));
  Iobuf.advance buf 4
;;

(** Emits a 'mov' instruction. *)
val mov : (_, _) t -> Condition -> bool -> Reg -> bool -> unit
let mov buf cond update_cprs rd update_condition =
  Iobuf.Poke.uint32_le buf ((((27262976 | cond) | (update_cprs << 20)) | (rd << 12)) | (update_condition << 20));
  Iobuf.advance buf 4
;;

(** Emits a 'mrrc' instruction. *)
val mrrc : (_, _) t -> Condition -> Reg -> Reg -> Coprocessor -> unit
let mrrc buf cond rn rd cpnum =
  Iobuf.Poke.uint32_le buf ((((206569472 | cond) | (rn << 16)) | (rd << 12)) | (cpnum << 8));
  Iobuf.advance buf 4
;;

(** Emits a 'mrs' instruction. *)
val mrs : (_, _) t -> Condition -> Reg -> unit
let mrs buf cond rd =
  Iobuf.Poke.uint32_le buf ((17760256 | cond) | (rd << 12));
  Iobuf.advance buf 4
;;

(** Emits a 'mul' instruction. *)
val mul : (_, _) t -> Condition -> bool -> Reg -> bool -> unit
let mul buf cond update_cprs rd update_condition =
  Iobuf.Poke.uint32_le buf ((((144 | cond) | (update_cprs << 20)) | (rd << 16)) | (update_condition << 20));
  Iobuf.advance buf 4
;;

(** Emits a 'mvn' instruction. *)
val mvn : (_, _) t -> Condition -> bool -> Reg -> bool -> unit
let mvn buf cond update_cprs rd update_condition =
  Iobuf.Poke.uint32_le buf ((((31457280 | cond) | (update_cprs << 20)) | (rd << 12)) | (update_condition << 20));
  Iobuf.advance buf 4
;;

(** Emits a 'msr_imm' instruction. *)
val msr_imm : (_, _) t -> Condition -> FieldMask -> unit
let msr_imm buf cond fieldmask =
  Iobuf.Poke.uint32_le buf ((52490240 | cond) | (fieldmask << 16));
  Iobuf.advance buf 4
;;

(** Emits a 'msr_reg' instruction. *)
val msr_reg : (_, _) t -> Condition -> FieldMask -> unit
let msr_reg buf cond fieldmask =
  Iobuf.Poke.uint32_le buf ((18935808 | cond) | (fieldmask << 16));
  Iobuf.advance buf 4
;;

(** Emits a 'pkhbt' instruction. *)
val pkhbt : (_, _) t -> Condition -> Reg -> Reg -> unit
let pkhbt buf cond rn rd =
  Iobuf.Poke.uint32_le buf (((109051920 | cond) | (rn << 16)) | (rd << 12));
  Iobuf.advance buf 4
;;

(** Emits a 'pkhtb' instruction. *)
val pkhtb : (_, _) t -> Condition -> Reg -> Reg -> unit
let pkhtb buf cond rn rd =
  Iobuf.Poke.uint32_le buf (((109051984 | cond) | (rn << 16)) | (rd << 12));
  Iobuf.advance buf 4
;;

(** Emits a 'pld' instruction. *)
val pld : (_, _) t -> Reg -> OffsetMode -> unit
let pld buf rn offset_mode =
  Iobuf.Poke.uint32_le buf ((4115722240 | (rn << 16)) | (offset_mode << 23));
  Iobuf.advance buf 4
;;

(** Emits a 'qadd' instruction. *)
val qadd : (_, _) t -> Condition -> Reg -> Reg -> unit
let qadd buf cond rn rd =
  Iobuf.Poke.uint32_le buf (((16777296 | cond) | (rn << 16)) | (rd << 12));
  Iobuf.advance buf 4
;;

(** Emits a 'qadd16' instruction. *)
val qadd16 : (_, _) t -> Condition -> Reg -> Reg -> unit
let qadd16 buf cond rn rd =
  Iobuf.Poke.uint32_le buf (((102764304 | cond) | (rn << 16)) | (rd << 12));
  Iobuf.advance buf 4
;;

(** Emits a 'qadd8' instruction. *)
val qadd8 : (_, _) t -> Condition -> Reg -> Reg -> unit
let qadd8 buf cond rn rd =
  Iobuf.Poke.uint32_le buf (((102764432 | cond) | (rn << 16)) | (rd << 12));
  Iobuf.advance buf 4
;;

(** Emits a 'qaddsubx' instruction. *)
val qaddsubx : (_, _) t -> Condition -> Reg -> Reg -> unit
let qaddsubx buf cond rn rd =
  Iobuf.Poke.uint32_le buf (((102764336 | cond) | (rn << 16)) | (rd << 12));
  Iobuf.advance buf 4
;;

(** Emits a 'qdadd' instruction. *)
val qdadd : (_, _) t -> Condition -> Reg -> Reg -> unit
let qdadd buf cond rn rd =
  Iobuf.Poke.uint32_le buf (((20971600 | cond) | (rn << 16)) | (rd << 12));
  Iobuf.advance buf 4
;;

(** Emits a 'qdsub' instruction. *)
val qdsub : (_, _) t -> Condition -> Reg -> Reg -> unit
let qdsub buf cond rn rd =
  Iobuf.Poke.uint32_le buf (((23068752 | cond) | (rn << 16)) | (rd << 12));
  Iobuf.advance buf 4
;;

(** Emits a 'qsub' instruction. *)
val qsub : (_, _) t -> Condition -> Reg -> Reg -> unit
let qsub buf cond rn rd =
  Iobuf.Poke.uint32_le buf (((18874448 | cond) | (rn << 16)) | (rd << 12));
  Iobuf.advance buf 4
;;

(** Emits a 'qsub16' instruction. *)
val qsub16 : (_, _) t -> Condition -> Reg -> Reg -> unit
let qsub16 buf cond rn rd =
  Iobuf.Poke.uint32_le buf (((102764400 | cond) | (rn << 16)) | (rd << 12));
  Iobuf.advance buf 4
;;

(** Emits a 'qsub8' instruction. *)
val qsub8 : (_, _) t -> Condition -> Reg -> Reg -> unit
let qsub8 buf cond rn rd =
  Iobuf.Poke.uint32_le buf (((102764528 | cond) | (rn << 16)) | (rd << 12));
  Iobuf.advance buf 4
;;

(** Emits a 'qsubaddx' instruction. *)
val qsubaddx : (_, _) t -> Condition -> Reg -> Reg -> unit
let qsubaddx buf cond rn rd =
  Iobuf.Poke.uint32_le buf (((102764368 | cond) | (rn << 16)) | (rd << 12));
  Iobuf.advance buf 4
;;

(** Emits a 'rev' instruction. *)
val rev : (_, _) t -> Condition -> Reg -> unit
let rev buf cond rd =
  Iobuf.Poke.uint32_le buf ((113184560 | cond) | (rd << 12));
  Iobuf.advance buf 4
;;

(** Emits a 'rev16' instruction. *)
val rev16 : (_, _) t -> Condition -> Reg -> unit
let rev16 buf cond rd =
  Iobuf.Poke.uint32_le buf ((113184688 | cond) | (rd << 12));
  Iobuf.advance buf 4
;;

(** Emits a 'revsh' instruction. *)
val revsh : (_, _) t -> Condition -> Reg -> unit
let revsh buf cond rd =
  Iobuf.Poke.uint32_le buf ((117378992 | cond) | (rd << 12));
  Iobuf.advance buf 4
;;

(** Emits a 'rfe' instruction. *)
val rfe : (_, _) t -> bool -> Reg -> OffsetMode -> Addressing -> unit
let rfe buf write rn offset_mode addressing_mode =
  Iobuf.Poke.uint32_le buf ((((4161800704 | (write << 21)) | (rn << 16)) | (addressing_mode << 23)) | (offset_mode << 11));
  Iobuf.advance buf 4
;;

(** Emits a 'sadd16' instruction. *)
val sadd16 : (_, _) t -> Condition -> Reg -> Reg -> unit
let sadd16 buf cond rn rd =
  Iobuf.Poke.uint32_le buf (((101715728 | cond) | (rn << 16)) | (rd << 12));
  Iobuf.advance buf 4
;;

(** Emits a 'sadd8' instruction. *)
val sadd8 : (_, _) t -> Condition -> Reg -> Reg -> unit
let sadd8 buf cond rn rd =
  Iobuf.Poke.uint32_le buf (((101715856 | cond) | (rn << 16)) | (rd << 12));
  Iobuf.advance buf 4
;;

(** Emits a 'saddsubx' instruction. *)
val saddsubx : (_, _) t -> Condition -> Reg -> Reg -> unit
let saddsubx buf cond rn rd =
  Iobuf.Poke.uint32_le buf (((101715760 | cond) | (rn << 16)) | (rd << 12));
  Iobuf.advance buf 4
;;

(** Emits a 'sel' instruction. *)
val sel : (_, _) t -> Condition -> Reg -> Reg -> unit
let sel buf cond rn rd =
  Iobuf.Poke.uint32_le buf (((109055920 | cond) | (rn << 16)) | (rd << 12));
  Iobuf.advance buf 4
;;

(** Emits a 'setendbe' instruction. *)
val setendbe : (_, _) t -> unit
let setendbe buf =
  Iobuf.Poke.uint32_le buf 4043375104;
  Iobuf.advance buf 4
;;

(** Emits a 'setendle' instruction. *)
val setendle : (_, _) t -> unit
let setendle buf =
  Iobuf.Poke.uint32_le buf 4043374592;
  Iobuf.advance buf 4
;;

(** Emits a 'shadd16' instruction. *)
val shadd16 : (_, _) t -> Condition -> Reg -> Reg -> unit
let shadd16 buf cond rn rd =
  Iobuf.Poke.uint32_le buf (((103812880 | cond) | (rn << 16)) | (rd << 12));
  Iobuf.advance buf 4
;;

(** Emits a 'shadd8' instruction. *)
val shadd8 : (_, _) t -> Condition -> Reg -> Reg -> unit
let shadd8 buf cond rn rd =
  Iobuf.Poke.uint32_le buf (((103813008 | cond) | (rn << 16)) | (rd << 12));
  Iobuf.advance buf 4
;;

(** Emits a 'shaddsubx' instruction. *)
val shaddsubx : (_, _) t -> Condition -> Reg -> Reg -> unit
let shaddsubx buf cond rn rd =
  Iobuf.Poke.uint32_le buf (((103812912 | cond) | (rn << 16)) | (rd << 12));
  Iobuf.advance buf 4
;;

(** Emits a 'shsub16' instruction. *)
val shsub16 : (_, _) t -> Condition -> Reg -> Reg -> unit
let shsub16 buf cond rn rd =
  Iobuf.Poke.uint32_le buf (((103812976 | cond) | (rn << 16)) | (rd << 12));
  Iobuf.advance buf 4
;;

(** Emits a 'shsub8' instruction. *)
val shsub8 : (_, _) t -> Condition -> Reg -> Reg -> unit
let shsub8 buf cond rn rd =
  Iobuf.Poke.uint32_le buf (((103813104 | cond) | (rn << 16)) | (rd << 12));
  Iobuf.advance buf 4
;;

(** Emits a 'shsubaddx' instruction. *)
val shsubaddx : (_, _) t -> Condition -> Reg -> Reg -> unit
let shsubaddx buf cond rn rd =
  Iobuf.Poke.uint32_le buf (((103812944 | cond) | (rn << 16)) | (rd << 12));
  Iobuf.advance buf 4
;;

(** Emits a 'smlabb' instruction. *)
val smlabb : (_, _) t -> Condition -> Reg -> Reg -> unit
let smlabb buf cond rn rd =
  Iobuf.Poke.uint32_le buf (((16777344 | cond) | (rn << 12)) | (rd << 16));
  Iobuf.advance buf 4
;;

(** Emits a 'smlabt' instruction. *)
val smlabt : (_, _) t -> Condition -> Reg -> Reg -> unit
let smlabt buf cond rn rd =
  Iobuf.Poke.uint32_le buf (((16777376 | cond) | (rn << 12)) | (rd << 16));
  Iobuf.advance buf 4
;;

(** Emits a 'smlatb' instruction. *)
val smlatb : (_, _) t -> Condition -> Reg -> Reg -> unit
let smlatb buf cond rn rd =
  Iobuf.Poke.uint32_le buf (((16777408 | cond) | (rn << 12)) | (rd << 16));
  Iobuf.advance buf 4
;;

(** Emits a 'smlatt' instruction. *)
val smlatt : (_, _) t -> Condition -> Reg -> Reg -> unit
let smlatt buf cond rn rd =
  Iobuf.Poke.uint32_le buf (((16777440 | cond) | (rn << 12)) | (rd << 16));
  Iobuf.advance buf 4
;;

(** Emits a 'smlad' instruction. *)
val smlad : (_, _) t -> Condition -> bool -> Reg -> Reg -> unit
let smlad buf cond exchange rn rd =
  Iobuf.Poke.uint32_le buf ((((117440528 | cond) | (exchange << 5)) | (rn << 12)) | (rd << 16));
  Iobuf.advance buf 4
;;

(** Emits a 'smlal' instruction. *)
val smlal : (_, _) t -> Condition -> bool -> bool -> unit
let smlal buf cond update_cprs update_condition =
  Iobuf.Poke.uint32_le buf (((14680208 | cond) | (update_cprs << 20)) | (update_condition << 20));
  Iobuf.advance buf 4
;;

(** Emits a 'smlalbb' instruction. *)
val smlalbb : (_, _) t -> Condition -> unit
let smlalbb buf cond =
  Iobuf.Poke.uint32_le buf (20971648 | cond);
  Iobuf.advance buf 4
;;

(** Emits a 'smlalbt' instruction. *)
val smlalbt : (_, _) t -> Condition -> unit
let smlalbt buf cond =
  Iobuf.Poke.uint32_le buf (20971680 | cond);
  Iobuf.advance buf 4
;;

(** Emits a 'smlaltb' instruction. *)
val smlaltb : (_, _) t -> Condition -> unit
let smlaltb buf cond =
  Iobuf.Poke.uint32_le buf (20971712 | cond);
  Iobuf.advance buf 4
;;

(** Emits a 'smlaltt' instruction. *)
val smlaltt : (_, _) t -> Condition -> unit
let smlaltt buf cond =
  Iobuf.Poke.uint32_le buf (20971744 | cond);
  Iobuf.advance buf 4
;;

(** Emits a 'smlald' instruction. *)
val smlald : (_, _) t -> Condition -> bool -> unit
let smlald buf cond exchange =
  Iobuf.Poke.uint32_le buf ((121634832 | cond) | (exchange << 5));
  Iobuf.advance buf 4
;;

(** Emits a 'smlawb' instruction. *)
val smlawb : (_, _) t -> Condition -> Reg -> Reg -> unit
let smlawb buf cond rn rd =
  Iobuf.Poke.uint32_le buf (((18874496 | cond) | (rn << 12)) | (rd << 16));
  Iobuf.advance buf 4
;;

(** Emits a 'smlawt' instruction. *)
val smlawt : (_, _) t -> Condition -> Reg -> Reg -> unit
let smlawt buf cond rn rd =
  Iobuf.Poke.uint32_le buf (((18874560 | cond) | (rn << 12)) | (rd << 16));
  Iobuf.advance buf 4
;;

(** Emits a 'smlsd' instruction. *)
val smlsd : (_, _) t -> Condition -> bool -> Reg -> Reg -> unit
let smlsd buf cond exchange rn rd =
  Iobuf.Poke.uint32_le buf ((((117440592 | cond) | (exchange << 5)) | (rn << 12)) | (rd << 16));
  Iobuf.advance buf 4
;;

(** Emits a 'smlsld' instruction. *)
val smlsld : (_, _) t -> Condition -> bool -> unit
let smlsld buf cond exchange =
  Iobuf.Poke.uint32_le buf ((121634896 | cond) | (exchange << 5));
  Iobuf.advance buf 4
;;

(** Emits a 'smmla' instruction. *)
val smmla : (_, _) t -> Condition -> Reg -> Reg -> unit
let smmla buf cond rn rd =
  Iobuf.Poke.uint32_le buf (((122683408 | cond) | (rn << 12)) | (rd << 16));
  Iobuf.advance buf 4
;;

(** Emits a 'smmls' instruction. *)
val smmls : (_, _) t -> Condition -> Reg -> Reg -> unit
let smmls buf cond rn rd =
  Iobuf.Poke.uint32_le buf (((122683600 | cond) | (rn << 12)) | (rd << 16));
  Iobuf.advance buf 4
;;

(** Emits a 'smmul' instruction. *)
val smmul : (_, _) t -> Condition -> Reg -> unit
let smmul buf cond rd =
  Iobuf.Poke.uint32_le buf ((122744848 | cond) | (rd << 16));
  Iobuf.advance buf 4
;;

(** Emits a 'smuad' instruction. *)
val smuad : (_, _) t -> Condition -> bool -> Reg -> unit
let smuad buf cond exchange rd =
  Iobuf.Poke.uint32_le buf (((117501968 | cond) | (exchange << 5)) | (rd << 16));
  Iobuf.advance buf 4
;;

(** Emits a 'smulbb' instruction. *)
val smulbb : (_, _) t -> Condition -> Reg -> unit
let smulbb buf cond rd =
  Iobuf.Poke.uint32_le buf ((23068800 | cond) | (rd << 16));
  Iobuf.advance buf 4
;;

(** Emits a 'smulbt' instruction. *)
val smulbt : (_, _) t -> Condition -> Reg -> unit
let smulbt buf cond rd =
  Iobuf.Poke.uint32_le buf ((23068832 | cond) | (rd << 16));
  Iobuf.advance buf 4
;;

(** Emits a 'smultb' instruction. *)
val smultb : (_, _) t -> Condition -> Reg -> unit
let smultb buf cond rd =
  Iobuf.Poke.uint32_le buf ((23068864 | cond) | (rd << 16));
  Iobuf.advance buf 4
;;

(** Emits a 'smultt' instruction. *)
val smultt : (_, _) t -> Condition -> Reg -> unit
let smultt buf cond rd =
  Iobuf.Poke.uint32_le buf ((23068896 | cond) | (rd << 16));
  Iobuf.advance buf 4
;;

(** Emits a 'smull' instruction. *)
val smull : (_, _) t -> Condition -> bool -> bool -> unit
let smull buf cond update_cprs update_condition =
  Iobuf.Poke.uint32_le buf (((12583056 | cond) | (update_cprs << 20)) | (update_condition << 20));
  Iobuf.advance buf 4
;;

(** Emits a 'smulwb' instruction. *)
val smulwb : (_, _) t -> Condition -> Reg -> unit
let smulwb buf cond rd =
  Iobuf.Poke.uint32_le buf ((18874528 | cond) | (rd << 16));
  Iobuf.advance buf 4
;;

(** Emits a 'smulwt' instruction. *)
val smulwt : (_, _) t -> Condition -> Reg -> unit
let smulwt buf cond rd =
  Iobuf.Poke.uint32_le buf ((18874592 | cond) | (rd << 16));
  Iobuf.advance buf 4
;;

(** Emits a 'smusd' instruction. *)
val smusd : (_, _) t -> Condition -> bool -> Reg -> unit
let smusd buf cond exchange rd =
  Iobuf.Poke.uint32_le buf (((117502032 | cond) | (exchange << 5)) | (rd << 16));
  Iobuf.advance buf 4
;;

(** Emits a 'srs' instruction. *)
val srs : (_, _) t -> bool -> Mode -> OffsetMode -> Addressing -> unit
let srs buf write mode offset_mode addressing_mode =
  Iobuf.Poke.uint32_le buf ((((4165797120 | (write << 21)) | (mode << 0)) | (addressing_mode << 23)) | (offset_mode << 11));
  Iobuf.advance buf 4
;;

(** Emits a 'ssat' instruction. *)
val ssat : (_, _) t -> Condition -> Reg -> unit
let ssat buf cond rd =
  Iobuf.Poke.uint32_le buf ((105906192 | cond) | (rd << 12));
  Iobuf.advance buf 4
;;

(** Emits a 'ssat16' instruction. *)
val ssat16 : (_, _) t -> Condition -> Reg -> unit
let ssat16 buf cond rd =
  Iobuf.Poke.uint32_le buf ((111152944 | cond) | (rd << 12));
  Iobuf.advance buf 4
;;

(** Emits a 'ssub16' instruction. *)
val ssub16 : (_, _) t -> Condition -> Reg -> Reg -> unit
let ssub16 buf cond rn rd =
  Iobuf.Poke.uint32_le buf (((101715824 | cond) | (rn << 16)) | (rd << 12));
  Iobuf.advance buf 4
;;

(** Emits a 'ssub8' instruction. *)
val ssub8 : (_, _) t -> Condition -> Reg -> Reg -> unit
let ssub8 buf cond rn rd =
  Iobuf.Poke.uint32_le buf (((101715952 | cond) | (rn << 16)) | (rd << 12));
  Iobuf.advance buf 4
;;

(** Emits a 'ssubaddx' instruction. *)
val ssubaddx : (_, _) t -> Condition -> Reg -> Reg -> unit
let ssubaddx buf cond rn rd =
  Iobuf.Poke.uint32_le buf (((101715792 | cond) | (rn << 16)) | (rd << 12));
  Iobuf.advance buf 4
;;

(** Emits a 'stc' instruction. *)
val stc : (_, _) t -> Condition -> bool -> Reg -> Coprocessor -> OffsetMode -> Addressing -> unit
let stc buf cond write rn cpnum offset_mode addressing_mode =
  Iobuf.Poke.uint32_le buf ((((((201326592 | cond) | (write << 21)) | (rn << 16)) | (cpnum << 8)) | (addressing_mode << 23)) | (offset_mode << 11));
  Iobuf.advance buf 4
;;

(** Emits a 'stm' instruction. *)
val stm : (_, _) t -> Condition -> Reg -> OffsetMode -> Addressing -> RegList -> bool -> bool -> unit
let stm buf cond rn offset_mode addressing_mode registers write user_mode =
  assert ((user_mode == 0) || (write == 0));
  Iobuf.Poke.uint32_le buf ((((((((134217728 | cond) | (rn << 16)) | (addressing_mode << 23)) | (offset_mode << 11)) | (addressing_mode << 23)) | registers) | (user_mode << 21)) | (write << 10));
  Iobuf.advance buf 4
;;

(** Emits a 'str' instruction. *)
val str : (_, _) t -> Condition -> bool -> Reg -> Reg -> OffsetMode -> Addressing -> unit
let str buf cond write rn rd offset_mode addressing_mode =
  Iobuf.Poke.uint32_le buf ((((((67108864 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11));
  Iobuf.advance buf 4
;;

(** Emits a 'strb' instruction. *)
val strb : (_, _) t -> Condition -> bool -> Reg -> Reg -> OffsetMode -> Addressing -> unit
let strb buf cond write rn rd offset_mode addressing_mode =
  Iobuf.Poke.uint32_le buf ((((((71303168 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11));
  Iobuf.advance buf 4
;;

(** Emits a 'strbt' instruction. *)
val strbt : (_, _) t -> Condition -> Reg -> Reg -> OffsetMode -> unit
let strbt buf cond rn rd offset_mode =
  Iobuf.Poke.uint32_le buf ((((73400320 | cond) | (rn << 16)) | (rd << 12)) | (offset_mode << 23));
  Iobuf.advance buf 4
;;

(** Emits a 'strd' instruction. *)
val strd : (_, _) t -> Condition -> bool -> Reg -> Reg -> OffsetMode -> Addressing -> unit
let strd buf cond write rn rd offset_mode addressing_mode =
  Iobuf.Poke.uint32_le buf ((((((240 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11));
  Iobuf.advance buf 4
;;

(** Emits a 'strex' instruction. *)
val strex : (_, _) t -> Condition -> Reg -> Reg -> unit
let strex buf cond rn rd =
  Iobuf.Poke.uint32_le buf (((25169808 | cond) | (rn << 16)) | (rd << 12));
  Iobuf.advance buf 4
;;

(** Emits a 'strh' instruction. *)
val strh : (_, _) t -> Condition -> bool -> Reg -> Reg -> OffsetMode -> Addressing -> unit
let strh buf cond write rn rd offset_mode addressing_mode =
  Iobuf.Poke.uint32_le buf ((((((176 | cond) | (write << 21)) | (rn << 16)) | (rd << 12)) | (addressing_mode << 23)) | (offset_mode << 11));
  Iobuf.advance buf 4
;;

(** Emits a 'strt' instruction. *)
val strt : (_, _) t -> Condition -> Reg -> Reg -> OffsetMode -> unit
let strt buf cond rn rd offset_mode =
  Iobuf.Poke.uint32_le buf ((((69206016 | cond) | (rn << 16)) | (rd << 12)) | (offset_mode << 23));
  Iobuf.advance buf 4
;;

(** Emits a 'swi' instruction. *)
val swi : (_, _) t -> Condition -> unit
let swi buf cond =
  Iobuf.Poke.uint32_le buf (251658240 | cond);
  Iobuf.advance buf 4
;;

(** Emits a 'swp' instruction. *)
val swp : (_, _) t -> Condition -> Reg -> Reg -> unit
let swp buf cond rn rd =
  Iobuf.Poke.uint32_le buf (((16777360 | cond) | (rn << 16)) | (rd << 12));
  Iobuf.advance buf 4
;;

(** Emits a 'swpb' instruction. *)
val swpb : (_, _) t -> Condition -> Reg -> Reg -> unit
let swpb buf cond rn rd =
  Iobuf.Poke.uint32_le buf (((20971664 | cond) | (rn << 16)) | (rd << 12));
  Iobuf.advance buf 4
;;

(** Emits a 'sxtab' instruction. *)
val sxtab : (_, _) t -> Condition -> Reg -> Reg -> Rotation -> unit
let sxtab buf cond rn rd rotate =
  Iobuf.Poke.uint32_le buf ((((111149168 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10));
  Iobuf.advance buf 4
;;

(** Emits a 'sxtab16' instruction. *)
val sxtab16 : (_, _) t -> Condition -> Reg -> Reg -> Rotation -> unit
let sxtab16 buf cond rn rd rotate =
  Iobuf.Poke.uint32_le buf ((((109052016 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10));
  Iobuf.advance buf 4
;;

(** Emits a 'sxtah' instruction. *)
val sxtah : (_, _) t -> Condition -> Reg -> Reg -> Rotation -> unit
let sxtah buf cond rn rd rotate =
  Iobuf.Poke.uint32_le buf ((((112197744 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10));
  Iobuf.advance buf 4
;;

(** Emits a 'sxtb' instruction. *)
val sxtb : (_, _) t -> Condition -> Reg -> Rotation -> unit
let sxtb buf cond rd rotate =
  Iobuf.Poke.uint32_le buf (((112132208 | cond) | (rd << 12)) | (rotate << 10));
  Iobuf.advance buf 4
;;

(** Emits a 'sxtb16' instruction. *)
val sxtb16 : (_, _) t -> Condition -> Reg -> Rotation -> unit
let sxtb16 buf cond rd rotate =
  Iobuf.Poke.uint32_le buf (((110035056 | cond) | (rd << 12)) | (rotate << 10));
  Iobuf.advance buf 4
;;

(** Emits a 'sxth' instruction. *)
val sxth : (_, _) t -> Condition -> Reg -> Rotation -> unit
let sxth buf cond rd rotate =
  Iobuf.Poke.uint32_le buf (((113180784 | cond) | (rd << 12)) | (rotate << 10));
  Iobuf.advance buf 4
;;

(** Emits a 'teq' instruction. *)
val teq : (_, _) t -> Condition -> Reg -> unit
let teq buf cond rn =
  Iobuf.Poke.uint32_le buf ((19922944 | cond) | (rn << 16));
  Iobuf.advance buf 4
;;

(** Emits a 'tst' instruction. *)
val tst : (_, _) t -> Condition -> Reg -> unit
let tst buf cond rn =
  Iobuf.Poke.uint32_le buf ((17825792 | cond) | (rn << 16));
  Iobuf.advance buf 4
;;

(** Emits an 'uadd16' instruction. *)
val uadd16 : (_, _) t -> Condition -> Reg -> Reg -> unit
let uadd16 buf cond rn rd =
  Iobuf.Poke.uint32_le buf (((105910032 | cond) | (rn << 16)) | (rd << 12));
  Iobuf.advance buf 4
;;

(** Emits an 'uadd8' instruction. *)
val uadd8 : (_, _) t -> Condition -> Reg -> Reg -> unit
let uadd8 buf cond rn rd =
  Iobuf.Poke.uint32_le buf (((105910160 | cond) | (rn << 16)) | (rd << 12));
  Iobuf.advance buf 4
;;

(** Emits an 'uaddsubx' instruction. *)
val uaddsubx : (_, _) t -> Condition -> Reg -> Reg -> unit
let uaddsubx buf cond rn rd =
  Iobuf.Poke.uint32_le buf (((105910064 | cond) | (rn << 16)) | (rd << 12));
  Iobuf.advance buf 4
;;

(** Emits an 'uhadd16' instruction. *)
val uhadd16 : (_, _) t -> Condition -> Reg -> Reg -> unit
let uhadd16 buf cond rn rd =
  Iobuf.Poke.uint32_le buf (((108007184 | cond) | (rn << 16)) | (rd << 12));
  Iobuf.advance buf 4
;;

(** Emits an 'uhadd8' instruction. *)
val uhadd8 : (_, _) t -> Condition -> Reg -> Reg -> unit
let uhadd8 buf cond rn rd =
  Iobuf.Poke.uint32_le buf (((108007312 | cond) | (rn << 16)) | (rd << 12));
  Iobuf.advance buf 4
;;

(** Emits an 'uhaddsubx' instruction. *)
val uhaddsubx : (_, _) t -> Condition -> Reg -> Reg -> unit
let uhaddsubx buf cond rn rd =
  Iobuf.Poke.uint32_le buf (((108007216 | cond) | (rn << 16)) | (rd << 12));
  Iobuf.advance buf 4
;;

(** Emits an 'uhsub16' instruction. *)
val uhsub16 : (_, _) t -> Condition -> Reg -> Reg -> unit
let uhsub16 buf cond rn rd =
  Iobuf.Poke.uint32_le buf (((108007280 | cond) | (rn << 16)) | (rd << 12));
  Iobuf.advance buf 4
;;

(** Emits an 'uhsub8' instruction. *)
val uhsub8 : (_, _) t -> Condition -> Reg -> Reg -> unit
let uhsub8 buf cond rn rd =
  Iobuf.Poke.uint32_le buf (((108007408 | cond) | (rn << 16)) | (rd << 12));
  Iobuf.advance buf 4
;;

(** Emits an 'uhsubaddx' instruction. *)
val uhsubaddx : (_, _) t -> Condition -> Reg -> Reg -> unit
let uhsubaddx buf cond rn rd =
  Iobuf.Poke.uint32_le buf (((108007248 | cond) | (rn << 16)) | (rd << 12));
  Iobuf.advance buf 4
;;

(** Emits an 'umaal' instruction. *)
val umaal : (_, _) t -> Condition -> unit
let umaal buf cond =
  Iobuf.Poke.uint32_le buf (4194448 | cond);
  Iobuf.advance buf 4
;;

(** Emits an 'umlal' instruction. *)
val umlal : (_, _) t -> Condition -> bool -> bool -> unit
let umlal buf cond update_cprs update_condition =
  Iobuf.Poke.uint32_le buf (((10485904 | cond) | (update_cprs << 20)) | (update_condition << 20));
  Iobuf.advance buf 4
;;

(** Emits an 'umull' instruction. *)
val umull : (_, _) t -> Condition -> bool -> bool -> unit
let umull buf cond update_cprs update_condition =
  Iobuf.Poke.uint32_le buf (((8388752 | cond) | (update_cprs << 20)) | (update_condition << 20));
  Iobuf.advance buf 4
;;

(** Emits an 'uqadd16' instruction. *)
val uqadd16 : (_, _) t -> Condition -> Reg -> Reg -> unit
let uqadd16 buf cond rn rd =
  Iobuf.Poke.uint32_le buf (((106958608 | cond) | (rn << 16)) | (rd << 12));
  Iobuf.advance buf 4
;;

(** Emits an 'uqadd8' instruction. *)
val uqadd8 : (_, _) t -> Condition -> Reg -> Reg -> unit
let uqadd8 buf cond rn rd =
  Iobuf.Poke.uint32_le buf (((106958736 | cond) | (rn << 16)) | (rd << 12));
  Iobuf.advance buf 4
;;

(** Emits an 'uqaddsubx' instruction. *)
val uqaddsubx : (_, _) t -> Condition -> Reg -> Reg -> unit
let uqaddsubx buf cond rn rd =
  Iobuf.Poke.uint32_le buf (((106958640 | cond) | (rn << 16)) | (rd << 12));
  Iobuf.advance buf 4
;;

(** Emits an 'uqsub16' instruction. *)
val uqsub16 : (_, _) t -> Condition -> Reg -> Reg -> unit
let uqsub16 buf cond rn rd =
  Iobuf.Poke.uint32_le buf (((106958704 | cond) | (rn << 16)) | (rd << 12));
  Iobuf.advance buf 4
;;

(** Emits an 'uqsub8' instruction. *)
val uqsub8 : (_, _) t -> Condition -> Reg -> Reg -> unit
let uqsub8 buf cond rn rd =
  Iobuf.Poke.uint32_le buf (((106958832 | cond) | (rn << 16)) | (rd << 12));
  Iobuf.advance buf 4
;;

(** Emits an 'uqsubaddx' instruction. *)
val uqsubaddx : (_, _) t -> Condition -> Reg -> Reg -> unit
let uqsubaddx buf cond rn rd =
  Iobuf.Poke.uint32_le buf (((106958672 | cond) | (rn << 16)) | (rd << 12));
  Iobuf.advance buf 4
;;

(** Emits an 'usad8' instruction. *)
val usad8 : (_, _) t -> Condition -> Reg -> unit
let usad8 buf cond rd =
  Iobuf.Poke.uint32_le buf ((125890576 | cond) | (rd << 16));
  Iobuf.advance buf 4
;;

(** Emits an 'usada8' instruction. *)
val usada8 : (_, _) t -> Condition -> Reg -> Reg -> unit
let usada8 buf cond rn rd =
  Iobuf.Poke.uint32_le buf (((125829136 | cond) | (rn << 12)) | (rd << 16));
  Iobuf.advance buf 4
;;

(** Emits an 'usat' instruction. *)
val usat : (_, _) t -> Condition -> Reg -> unit
let usat buf cond rd =
  Iobuf.Poke.uint32_le buf ((115343376 | cond) | (rd << 12));
  Iobuf.advance buf 4
;;

(** Emits an 'usat16' instruction. *)
val usat16 : (_, _) t -> Condition -> Reg -> unit
let usat16 buf cond rd =
  Iobuf.Poke.uint32_le buf ((115347248 | cond) | (rd << 12));
  Iobuf.advance buf 4
;;

(** Emits an 'usub16' instruction. *)
val usub16 : (_, _) t -> Condition -> Reg -> Reg -> unit
let usub16 buf cond rn rd =
  Iobuf.Poke.uint32_le buf (((105910128 | cond) | (rn << 16)) | (rd << 12));
  Iobuf.advance buf 4
;;

(** Emits an 'usub8' instruction. *)
val usub8 : (_, _) t -> Condition -> Reg -> Reg -> unit
let usub8 buf cond rn rd =
  Iobuf.Poke.uint32_le buf (((105910256 | cond) | (rn << 16)) | (rd << 12));
  Iobuf.advance buf 4
;;

(** Emits an 'usubaddx' instruction. *)
val usubaddx : (_, _) t -> Condition -> Reg -> Reg -> unit
let usubaddx buf cond rn rd =
  Iobuf.Poke.uint32_le buf (((105910096 | cond) | (rn << 16)) | (rd << 12));
  Iobuf.advance buf 4
;;

(** Emits an 'uxtab' instruction. *)
val uxtab : (_, _) t -> Condition -> Reg -> Reg -> Rotation -> unit
let uxtab buf cond rn rd rotate =
  Iobuf.Poke.uint32_le buf ((((115343472 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10));
  Iobuf.advance buf 4
;;

(** Emits an 'uxtab16' instruction. *)
val uxtab16 : (_, _) t -> Condition -> Reg -> Reg -> Rotation -> unit
let uxtab16 buf cond rn rd rotate =
  Iobuf.Poke.uint32_le buf ((((113246320 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10));
  Iobuf.advance buf 4
;;

(** Emits an 'uxtah' instruction. *)
val uxtah : (_, _) t -> Condition -> Reg -> Reg -> Rotation -> unit
let uxtah buf cond rn rd rotate =
  Iobuf.Poke.uint32_le buf ((((116392048 | cond) | (rn << 16)) | (rd << 12)) | (rotate << 10));
  Iobuf.advance buf 4
;;

(** Emits an 'uxtb' instruction. *)
val uxtb : (_, _) t -> Condition -> Reg -> Rotation -> unit
let uxtb buf cond rd rotate =
  Iobuf.Poke.uint32_le buf (((116326512 | cond) | (rd << 12)) | (rotate << 10));
  Iobuf.advance buf 4
;;

(** Emits an 'uxtb16' instruction. *)
val uxtb16 : (_, _) t -> Condition -> Reg -> Rotation -> unit
let uxtb16 buf cond rd rotate =
  Iobuf.Poke.uint32_le buf (((114229360 | cond) | (rd << 12)) | (rotate << 10));
  Iobuf.advance buf 4
;;

(** Emits an 'uxth' instruction. *)
val uxth : (_, _) t -> Condition -> Reg -> Rotation -> unit
let uxth buf cond rd rotate =
  Iobuf.Poke.uint32_le buf (((117375088 | cond) | (rd << 12)) | (rotate << 10));
  Iobuf.advance buf 4
;;

