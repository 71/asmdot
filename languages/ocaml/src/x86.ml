open Core

(** An x86 8-bits register. *)
type Reg8 = uint8
module Reg8
  let al = Reg8 0 ;;
  let cl = Reg8 1 ;;
  let dl = Reg8 2 ;;
  let bl = Reg8 3 ;;
  let spl = Reg8 4 ;;
  let bpl = Reg8 5 ;;
  let sil = Reg8 6 ;;
  let dil = Reg8 7 ;;
  let r8b = Reg8 8 ;;
  let r9b = Reg8 9 ;;
  let r10b = Reg8 10 ;;
  let r11b = Reg8 11 ;;
  let r12b = Reg8 12 ;;
  let r13b = Reg8 13 ;;
  let r14b = Reg8 14 ;;
  let r15b = Reg8 15 ;;
;;

(** An x86 16-bits register. *)
type Reg16 = uint8
module Reg16
  let ax = Reg16 0 ;;
  let cx = Reg16 1 ;;
  let dx = Reg16 2 ;;
  let bx = Reg16 3 ;;
  let sp = Reg16 4 ;;
  let bp = Reg16 5 ;;
  let si = Reg16 6 ;;
  let di = Reg16 7 ;;
  let r8w = Reg16 8 ;;
  let r9w = Reg16 9 ;;
  let r10w = Reg16 10 ;;
  let r11w = Reg16 11 ;;
  let r12w = Reg16 12 ;;
  let r13w = Reg16 13 ;;
  let r14w = Reg16 14 ;;
  let r15w = Reg16 15 ;;
;;

(** An x86 32-bits register. *)
type Reg32 = uint8
module Reg32
  let eax = Reg32 0 ;;
  let ecx = Reg32 1 ;;
  let edx = Reg32 2 ;;
  let ebx = Reg32 3 ;;
  let esp = Reg32 4 ;;
  let ebp = Reg32 5 ;;
  let esi = Reg32 6 ;;
  let edi = Reg32 7 ;;
  let r8d = Reg32 8 ;;
  let r9d = Reg32 9 ;;
  let r10d = Reg32 10 ;;
  let r11d = Reg32 11 ;;
  let r12d = Reg32 12 ;;
  let r13d = Reg32 13 ;;
  let r14d = Reg32 14 ;;
  let r15d = Reg32 15 ;;
;;

(** An x86 64-bits register. *)
type Reg64 = uint8
module Reg64
  let rax = Reg64 0 ;;
  let rcx = Reg64 1 ;;
  let rdx = Reg64 2 ;;
  let rbx = Reg64 3 ;;
  let rsp = Reg64 4 ;;
  let rbp = Reg64 5 ;;
  let rsi = Reg64 6 ;;
  let rdi = Reg64 7 ;;
  let r8 = Reg64 8 ;;
  let r9 = Reg64 9 ;;
  let r10 = Reg64 10 ;;
  let r11 = Reg64 11 ;;
  let r12 = Reg64 12 ;;
  let r13 = Reg64 13 ;;
  let r14 = Reg64 14 ;;
  let r15 = Reg64 15 ;;
;;

(** An x86 128-bits register. *)
type Reg128 = uint8


(** Emits a 'pushf' instruction. *)
val pushf : (_, _) t -> unit
let pushf buf =
  Iobuf.Poke.uint8 buf 156;
  Iobuf.advance buf 1
;;

(** Emits a 'popf' instruction. *)
val popf : (_, _) t -> unit
let popf buf =
  Iobuf.Poke.uint8 buf 157;
  Iobuf.advance buf 1
;;

(** Emits a 'ret' instruction. *)
val ret : (_, _) t -> unit
let ret buf =
  Iobuf.Poke.uint8 buf 195;
  Iobuf.advance buf 1
;;

(** Emits a 'clc' instruction. *)
val clc : (_, _) t -> unit
let clc buf =
  Iobuf.Poke.uint8 buf 248;
  Iobuf.advance buf 1
;;

(** Emits a 'stc' instruction. *)
val stc : (_, _) t -> unit
let stc buf =
  Iobuf.Poke.uint8 buf 249;
  Iobuf.advance buf 1
;;

(** Emits a 'cli' instruction. *)
val cli : (_, _) t -> unit
let cli buf =
  Iobuf.Poke.uint8 buf 250;
  Iobuf.advance buf 1
;;

(** Emits a 'sti' instruction. *)
val sti : (_, _) t -> unit
let sti buf =
  Iobuf.Poke.uint8 buf 251;
  Iobuf.advance buf 1
;;

(** Emits a 'cld' instruction. *)
val cld : (_, _) t -> unit
let cld buf =
  Iobuf.Poke.uint8 buf 252;
  Iobuf.advance buf 1
;;

(** Emits a 'std' instruction. *)
val std : (_, _) t -> unit
let std buf =
  Iobuf.Poke.uint8 buf 253;
  Iobuf.advance buf 1
;;

(** Emits a 'jo' instruction. *)
val jo_imm8 : (_, _) t -> int8 -> unit
let jo_imm8 buf operand =
  Iobuf.Poke.uint8 buf 112;
  Iobuf.advance buf 1
  Iobuf.Poke.int8 buf operand;
  Iobuf.advance buf 1
;;

(** Emits a 'jno' instruction. *)
val jno_imm8 : (_, _) t -> int8 -> unit
let jno_imm8 buf operand =
  Iobuf.Poke.uint8 buf 113;
  Iobuf.advance buf 1
  Iobuf.Poke.int8 buf operand;
  Iobuf.advance buf 1
;;

(** Emits a 'jb' instruction. *)
val jb_imm8 : (_, _) t -> int8 -> unit
let jb_imm8 buf operand =
  Iobuf.Poke.uint8 buf 114;
  Iobuf.advance buf 1
  Iobuf.Poke.int8 buf operand;
  Iobuf.advance buf 1
;;

(** Emits a 'jnae' instruction. *)
val jnae_imm8 : (_, _) t -> int8 -> unit
let jnae_imm8 buf operand =
  Iobuf.Poke.uint8 buf 114;
  Iobuf.advance buf 1
  Iobuf.Poke.int8 buf operand;
  Iobuf.advance buf 1
;;

(** Emits a 'jc' instruction. *)
val jc_imm8 : (_, _) t -> int8 -> unit
let jc_imm8 buf operand =
  Iobuf.Poke.uint8 buf 114;
  Iobuf.advance buf 1
  Iobuf.Poke.int8 buf operand;
  Iobuf.advance buf 1
;;

(** Emits a 'jnb' instruction. *)
val jnb_imm8 : (_, _) t -> int8 -> unit
let jnb_imm8 buf operand =
  Iobuf.Poke.uint8 buf 115;
  Iobuf.advance buf 1
  Iobuf.Poke.int8 buf operand;
  Iobuf.advance buf 1
;;

(** Emits a 'jae' instruction. *)
val jae_imm8 : (_, _) t -> int8 -> unit
let jae_imm8 buf operand =
  Iobuf.Poke.uint8 buf 115;
  Iobuf.advance buf 1
  Iobuf.Poke.int8 buf operand;
  Iobuf.advance buf 1
;;

(** Emits a 'jnc' instruction. *)
val jnc_imm8 : (_, _) t -> int8 -> unit
let jnc_imm8 buf operand =
  Iobuf.Poke.uint8 buf 115;
  Iobuf.advance buf 1
  Iobuf.Poke.int8 buf operand;
  Iobuf.advance buf 1
;;

(** Emits a 'jz' instruction. *)
val jz_imm8 : (_, _) t -> int8 -> unit
let jz_imm8 buf operand =
  Iobuf.Poke.uint8 buf 116;
  Iobuf.advance buf 1
  Iobuf.Poke.int8 buf operand;
  Iobuf.advance buf 1
;;

(** Emits a 'je' instruction. *)
val je_imm8 : (_, _) t -> int8 -> unit
let je_imm8 buf operand =
  Iobuf.Poke.uint8 buf 116;
  Iobuf.advance buf 1
  Iobuf.Poke.int8 buf operand;
  Iobuf.advance buf 1
;;

(** Emits a 'jnz' instruction. *)
val jnz_imm8 : (_, _) t -> int8 -> unit
let jnz_imm8 buf operand =
  Iobuf.Poke.uint8 buf 117;
  Iobuf.advance buf 1
  Iobuf.Poke.int8 buf operand;
  Iobuf.advance buf 1
;;

(** Emits a 'jne' instruction. *)
val jne_imm8 : (_, _) t -> int8 -> unit
let jne_imm8 buf operand =
  Iobuf.Poke.uint8 buf 117;
  Iobuf.advance buf 1
  Iobuf.Poke.int8 buf operand;
  Iobuf.advance buf 1
;;

(** Emits a 'jbe' instruction. *)
val jbe_imm8 : (_, _) t -> int8 -> unit
let jbe_imm8 buf operand =
  Iobuf.Poke.uint8 buf 118;
  Iobuf.advance buf 1
  Iobuf.Poke.int8 buf operand;
  Iobuf.advance buf 1
;;

(** Emits a 'jna' instruction. *)
val jna_imm8 : (_, _) t -> int8 -> unit
let jna_imm8 buf operand =
  Iobuf.Poke.uint8 buf 118;
  Iobuf.advance buf 1
  Iobuf.Poke.int8 buf operand;
  Iobuf.advance buf 1
;;

(** Emits a 'jnbe' instruction. *)
val jnbe_imm8 : (_, _) t -> int8 -> unit
let jnbe_imm8 buf operand =
  Iobuf.Poke.uint8 buf 119;
  Iobuf.advance buf 1
  Iobuf.Poke.int8 buf operand;
  Iobuf.advance buf 1
;;

(** Emits a 'ja' instruction. *)
val ja_imm8 : (_, _) t -> int8 -> unit
let ja_imm8 buf operand =
  Iobuf.Poke.uint8 buf 119;
  Iobuf.advance buf 1
  Iobuf.Poke.int8 buf operand;
  Iobuf.advance buf 1
;;

(** Emits a 'js' instruction. *)
val js_imm8 : (_, _) t -> int8 -> unit
let js_imm8 buf operand =
  Iobuf.Poke.uint8 buf 120;
  Iobuf.advance buf 1
  Iobuf.Poke.int8 buf operand;
  Iobuf.advance buf 1
;;

(** Emits a 'jns' instruction. *)
val jns_imm8 : (_, _) t -> int8 -> unit
let jns_imm8 buf operand =
  Iobuf.Poke.uint8 buf 121;
  Iobuf.advance buf 1
  Iobuf.Poke.int8 buf operand;
  Iobuf.advance buf 1
;;

(** Emits a 'jp' instruction. *)
val jp_imm8 : (_, _) t -> int8 -> unit
let jp_imm8 buf operand =
  Iobuf.Poke.uint8 buf 122;
  Iobuf.advance buf 1
  Iobuf.Poke.int8 buf operand;
  Iobuf.advance buf 1
;;

(** Emits a 'jpe' instruction. *)
val jpe_imm8 : (_, _) t -> int8 -> unit
let jpe_imm8 buf operand =
  Iobuf.Poke.uint8 buf 122;
  Iobuf.advance buf 1
  Iobuf.Poke.int8 buf operand;
  Iobuf.advance buf 1
;;

(** Emits a 'jnp' instruction. *)
val jnp_imm8 : (_, _) t -> int8 -> unit
let jnp_imm8 buf operand =
  Iobuf.Poke.uint8 buf 123;
  Iobuf.advance buf 1
  Iobuf.Poke.int8 buf operand;
  Iobuf.advance buf 1
;;

(** Emits a 'jpo' instruction. *)
val jpo_imm8 : (_, _) t -> int8 -> unit
let jpo_imm8 buf operand =
  Iobuf.Poke.uint8 buf 123;
  Iobuf.advance buf 1
  Iobuf.Poke.int8 buf operand;
  Iobuf.advance buf 1
;;

(** Emits a 'jl' instruction. *)
val jl_imm8 : (_, _) t -> int8 -> unit
let jl_imm8 buf operand =
  Iobuf.Poke.uint8 buf 124;
  Iobuf.advance buf 1
  Iobuf.Poke.int8 buf operand;
  Iobuf.advance buf 1
;;

(** Emits a 'jnge' instruction. *)
val jnge_imm8 : (_, _) t -> int8 -> unit
let jnge_imm8 buf operand =
  Iobuf.Poke.uint8 buf 124;
  Iobuf.advance buf 1
  Iobuf.Poke.int8 buf operand;
  Iobuf.advance buf 1
;;

(** Emits a 'jnl' instruction. *)
val jnl_imm8 : (_, _) t -> int8 -> unit
let jnl_imm8 buf operand =
  Iobuf.Poke.uint8 buf 125;
  Iobuf.advance buf 1
  Iobuf.Poke.int8 buf operand;
  Iobuf.advance buf 1
;;

(** Emits a 'jge' instruction. *)
val jge_imm8 : (_, _) t -> int8 -> unit
let jge_imm8 buf operand =
  Iobuf.Poke.uint8 buf 125;
  Iobuf.advance buf 1
  Iobuf.Poke.int8 buf operand;
  Iobuf.advance buf 1
;;

(** Emits a 'jle' instruction. *)
val jle_imm8 : (_, _) t -> int8 -> unit
let jle_imm8 buf operand =
  Iobuf.Poke.uint8 buf 126;
  Iobuf.advance buf 1
  Iobuf.Poke.int8 buf operand;
  Iobuf.advance buf 1
;;

(** Emits a 'jng' instruction. *)
val jng_imm8 : (_, _) t -> int8 -> unit
let jng_imm8 buf operand =
  Iobuf.Poke.uint8 buf 126;
  Iobuf.advance buf 1
  Iobuf.Poke.int8 buf operand;
  Iobuf.advance buf 1
;;

(** Emits a 'jnle' instruction. *)
val jnle_imm8 : (_, _) t -> int8 -> unit
let jnle_imm8 buf operand =
  Iobuf.Poke.uint8 buf 127;
  Iobuf.advance buf 1
  Iobuf.Poke.int8 buf operand;
  Iobuf.advance buf 1
;;

(** Emits a 'jg' instruction. *)
val jg_imm8 : (_, _) t -> int8 -> unit
let jg_imm8 buf operand =
  Iobuf.Poke.uint8 buf 127;
  Iobuf.advance buf 1
  Iobuf.Poke.int8 buf operand;
  Iobuf.advance buf 1
;;

(** Emits an 'inc' instruction. *)
val inc_r16 : (_, _) t -> Reg16 -> unit
let inc_r16 buf operand =
  Iobuf.Poke.uint8 buf (102 + get_prefix operand);
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (64 + operand);
  Iobuf.advance buf 1
;;

(** Emits an 'inc' instruction. *)
val inc_r32 : (_, _) t -> Reg32 -> unit
let inc_r32 buf operand =
  if (operand > 7) then
    Iobuf.Poke.uint8 buf 65;
    Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (64 + operand);
  Iobuf.advance buf 1
;;

(** Emits a 'dec' instruction. *)
val dec_r16 : (_, _) t -> Reg16 -> unit
let dec_r16 buf operand =
  Iobuf.Poke.uint8 buf (102 + get_prefix operand);
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (72 + operand);
  Iobuf.advance buf 1
;;

(** Emits a 'dec' instruction. *)
val dec_r32 : (_, _) t -> Reg32 -> unit
let dec_r32 buf operand =
  if (operand > 7) then
    Iobuf.Poke.uint8 buf 65;
    Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (72 + operand);
  Iobuf.advance buf 1
;;

(** Emits a 'push' instruction. *)
val push_r16 : (_, _) t -> Reg16 -> unit
let push_r16 buf operand =
  Iobuf.Poke.uint8 buf (102 + get_prefix operand);
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (80 + operand);
  Iobuf.advance buf 1
;;

(** Emits a 'push' instruction. *)
val push_r32 : (_, _) t -> Reg32 -> unit
let push_r32 buf operand =
  if (operand > 7) then
    Iobuf.Poke.uint8 buf 65;
    Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (80 + operand);
  Iobuf.advance buf 1
;;

(** Emits a 'pop' instruction. *)
val pop_r16 : (_, _) t -> Reg16 -> unit
let pop_r16 buf operand =
  Iobuf.Poke.uint8 buf (102 + get_prefix operand);
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (88 + operand);
  Iobuf.advance buf 1
;;

(** Emits a 'pop' instruction. *)
val pop_r32 : (_, _) t -> Reg32 -> unit
let pop_r32 buf operand =
  if (operand > 7) then
    Iobuf.Poke.uint8 buf 65;
    Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (88 + operand);
  Iobuf.advance buf 1
;;

(** Emits a 'pop' instruction. *)
val pop_r64 : (_, _) t -> Reg64 -> unit
let pop_r64 buf operand =
  Iobuf.Poke.uint8 buf (72 + get_prefix operand);
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (88 + operand);
  Iobuf.advance buf 1
;;

(** Emits an 'add' instruction. *)
val add_rm8_imm8 : (_, _) t -> Reg8 -> int8 -> unit
let add_rm8_imm8 buf reg value =
  Iobuf.Poke.uint8 buf 128;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (reg + 0);
  Iobuf.advance buf 1
  Iobuf.Poke.int8 buf value;
  Iobuf.advance buf 1
;;

(** Emits an 'or' instruction. *)
val or_rm8_imm8 : (_, _) t -> Reg8 -> int8 -> unit
let or_rm8_imm8 buf reg value =
  Iobuf.Poke.uint8 buf 128;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (reg + 1);
  Iobuf.advance buf 1
  Iobuf.Poke.int8 buf value;
  Iobuf.advance buf 1
;;

(** Emits an 'adc' instruction. *)
val adc_rm8_imm8 : (_, _) t -> Reg8 -> int8 -> unit
let adc_rm8_imm8 buf reg value =
  Iobuf.Poke.uint8 buf 128;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (reg + 2);
  Iobuf.advance buf 1
  Iobuf.Poke.int8 buf value;
  Iobuf.advance buf 1
;;

(** Emits a 'sbb' instruction. *)
val sbb_rm8_imm8 : (_, _) t -> Reg8 -> int8 -> unit
let sbb_rm8_imm8 buf reg value =
  Iobuf.Poke.uint8 buf 128;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (reg + 3);
  Iobuf.advance buf 1
  Iobuf.Poke.int8 buf value;
  Iobuf.advance buf 1
;;

(** Emits an 'and' instruction. *)
val and_rm8_imm8 : (_, _) t -> Reg8 -> int8 -> unit
let and_rm8_imm8 buf reg value =
  Iobuf.Poke.uint8 buf 128;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (reg + 4);
  Iobuf.advance buf 1
  Iobuf.Poke.int8 buf value;
  Iobuf.advance buf 1
;;

(** Emits a 'sub' instruction. *)
val sub_rm8_imm8 : (_, _) t -> Reg8 -> int8 -> unit
let sub_rm8_imm8 buf reg value =
  Iobuf.Poke.uint8 buf 128;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (reg + 5);
  Iobuf.advance buf 1
  Iobuf.Poke.int8 buf value;
  Iobuf.advance buf 1
;;

(** Emits a 'xor' instruction. *)
val xor_rm8_imm8 : (_, _) t -> Reg8 -> int8 -> unit
let xor_rm8_imm8 buf reg value =
  Iobuf.Poke.uint8 buf 128;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (reg + 6);
  Iobuf.advance buf 1
  Iobuf.Poke.int8 buf value;
  Iobuf.advance buf 1
;;

(** Emits a 'cmp' instruction. *)
val cmp_rm8_imm8 : (_, _) t -> Reg8 -> int8 -> unit
let cmp_rm8_imm8 buf reg value =
  Iobuf.Poke.uint8 buf 128;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (reg + 7);
  Iobuf.advance buf 1
  Iobuf.Poke.int8 buf value;
  Iobuf.advance buf 1
;;

(** Emits an 'add' instruction. *)
val add_rm16_imm16 : (_, _) t -> Reg16 -> int16 -> unit
let add_rm16_imm16 buf reg value =
  Iobuf.Poke.uint8 buf 102;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf 129;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (reg + 0);
  Iobuf.advance buf 1
  Iobuf.Poke.int16_le buf value;
  Iobuf.advance buf 2
;;

(** Emits an 'add' instruction. *)
val add_rm16_imm32 : (_, _) t -> Reg16 -> int32 -> unit
let add_rm16_imm32 buf reg value =
  Iobuf.Poke.uint8 buf 102;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf 129;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (reg + 0);
  Iobuf.advance buf 1
  Iobuf.Poke.int32_le buf value;
  Iobuf.advance buf 4
;;

(** Emits an 'add' instruction. *)
val add_rm32_imm16 : (_, _) t -> Reg32 -> int16 -> unit
let add_rm32_imm16 buf reg value =
  Iobuf.Poke.uint8 buf 129;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (reg + 0);
  Iobuf.advance buf 1
  Iobuf.Poke.int16_le buf value;
  Iobuf.advance buf 2
;;

(** Emits an 'add' instruction. *)
val add_rm32_imm32 : (_, _) t -> Reg32 -> int32 -> unit
let add_rm32_imm32 buf reg value =
  Iobuf.Poke.uint8 buf 129;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (reg + 0);
  Iobuf.advance buf 1
  Iobuf.Poke.int32_le buf value;
  Iobuf.advance buf 4
;;

(** Emits an 'or' instruction. *)
val or_rm16_imm16 : (_, _) t -> Reg16 -> int16 -> unit
let or_rm16_imm16 buf reg value =
  Iobuf.Poke.uint8 buf 102;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf 129;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (reg + 1);
  Iobuf.advance buf 1
  Iobuf.Poke.int16_le buf value;
  Iobuf.advance buf 2
;;

(** Emits an 'or' instruction. *)
val or_rm16_imm32 : (_, _) t -> Reg16 -> int32 -> unit
let or_rm16_imm32 buf reg value =
  Iobuf.Poke.uint8 buf 102;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf 129;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (reg + 1);
  Iobuf.advance buf 1
  Iobuf.Poke.int32_le buf value;
  Iobuf.advance buf 4
;;

(** Emits an 'or' instruction. *)
val or_rm32_imm16 : (_, _) t -> Reg32 -> int16 -> unit
let or_rm32_imm16 buf reg value =
  Iobuf.Poke.uint8 buf 129;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (reg + 1);
  Iobuf.advance buf 1
  Iobuf.Poke.int16_le buf value;
  Iobuf.advance buf 2
;;

(** Emits an 'or' instruction. *)
val or_rm32_imm32 : (_, _) t -> Reg32 -> int32 -> unit
let or_rm32_imm32 buf reg value =
  Iobuf.Poke.uint8 buf 129;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (reg + 1);
  Iobuf.advance buf 1
  Iobuf.Poke.int32_le buf value;
  Iobuf.advance buf 4
;;

(** Emits an 'adc' instruction. *)
val adc_rm16_imm16 : (_, _) t -> Reg16 -> int16 -> unit
let adc_rm16_imm16 buf reg value =
  Iobuf.Poke.uint8 buf 102;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf 129;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (reg + 2);
  Iobuf.advance buf 1
  Iobuf.Poke.int16_le buf value;
  Iobuf.advance buf 2
;;

(** Emits an 'adc' instruction. *)
val adc_rm16_imm32 : (_, _) t -> Reg16 -> int32 -> unit
let adc_rm16_imm32 buf reg value =
  Iobuf.Poke.uint8 buf 102;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf 129;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (reg + 2);
  Iobuf.advance buf 1
  Iobuf.Poke.int32_le buf value;
  Iobuf.advance buf 4
;;

(** Emits an 'adc' instruction. *)
val adc_rm32_imm16 : (_, _) t -> Reg32 -> int16 -> unit
let adc_rm32_imm16 buf reg value =
  Iobuf.Poke.uint8 buf 129;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (reg + 2);
  Iobuf.advance buf 1
  Iobuf.Poke.int16_le buf value;
  Iobuf.advance buf 2
;;

(** Emits an 'adc' instruction. *)
val adc_rm32_imm32 : (_, _) t -> Reg32 -> int32 -> unit
let adc_rm32_imm32 buf reg value =
  Iobuf.Poke.uint8 buf 129;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (reg + 2);
  Iobuf.advance buf 1
  Iobuf.Poke.int32_le buf value;
  Iobuf.advance buf 4
;;

(** Emits a 'sbb' instruction. *)
val sbb_rm16_imm16 : (_, _) t -> Reg16 -> int16 -> unit
let sbb_rm16_imm16 buf reg value =
  Iobuf.Poke.uint8 buf 102;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf 129;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (reg + 3);
  Iobuf.advance buf 1
  Iobuf.Poke.int16_le buf value;
  Iobuf.advance buf 2
;;

(** Emits a 'sbb' instruction. *)
val sbb_rm16_imm32 : (_, _) t -> Reg16 -> int32 -> unit
let sbb_rm16_imm32 buf reg value =
  Iobuf.Poke.uint8 buf 102;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf 129;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (reg + 3);
  Iobuf.advance buf 1
  Iobuf.Poke.int32_le buf value;
  Iobuf.advance buf 4
;;

(** Emits a 'sbb' instruction. *)
val sbb_rm32_imm16 : (_, _) t -> Reg32 -> int16 -> unit
let sbb_rm32_imm16 buf reg value =
  Iobuf.Poke.uint8 buf 129;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (reg + 3);
  Iobuf.advance buf 1
  Iobuf.Poke.int16_le buf value;
  Iobuf.advance buf 2
;;

(** Emits a 'sbb' instruction. *)
val sbb_rm32_imm32 : (_, _) t -> Reg32 -> int32 -> unit
let sbb_rm32_imm32 buf reg value =
  Iobuf.Poke.uint8 buf 129;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (reg + 3);
  Iobuf.advance buf 1
  Iobuf.Poke.int32_le buf value;
  Iobuf.advance buf 4
;;

(** Emits an 'and' instruction. *)
val and_rm16_imm16 : (_, _) t -> Reg16 -> int16 -> unit
let and_rm16_imm16 buf reg value =
  Iobuf.Poke.uint8 buf 102;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf 129;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (reg + 4);
  Iobuf.advance buf 1
  Iobuf.Poke.int16_le buf value;
  Iobuf.advance buf 2
;;

(** Emits an 'and' instruction. *)
val and_rm16_imm32 : (_, _) t -> Reg16 -> int32 -> unit
let and_rm16_imm32 buf reg value =
  Iobuf.Poke.uint8 buf 102;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf 129;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (reg + 4);
  Iobuf.advance buf 1
  Iobuf.Poke.int32_le buf value;
  Iobuf.advance buf 4
;;

(** Emits an 'and' instruction. *)
val and_rm32_imm16 : (_, _) t -> Reg32 -> int16 -> unit
let and_rm32_imm16 buf reg value =
  Iobuf.Poke.uint8 buf 129;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (reg + 4);
  Iobuf.advance buf 1
  Iobuf.Poke.int16_le buf value;
  Iobuf.advance buf 2
;;

(** Emits an 'and' instruction. *)
val and_rm32_imm32 : (_, _) t -> Reg32 -> int32 -> unit
let and_rm32_imm32 buf reg value =
  Iobuf.Poke.uint8 buf 129;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (reg + 4);
  Iobuf.advance buf 1
  Iobuf.Poke.int32_le buf value;
  Iobuf.advance buf 4
;;

(** Emits a 'sub' instruction. *)
val sub_rm16_imm16 : (_, _) t -> Reg16 -> int16 -> unit
let sub_rm16_imm16 buf reg value =
  Iobuf.Poke.uint8 buf 102;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf 129;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (reg + 5);
  Iobuf.advance buf 1
  Iobuf.Poke.int16_le buf value;
  Iobuf.advance buf 2
;;

(** Emits a 'sub' instruction. *)
val sub_rm16_imm32 : (_, _) t -> Reg16 -> int32 -> unit
let sub_rm16_imm32 buf reg value =
  Iobuf.Poke.uint8 buf 102;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf 129;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (reg + 5);
  Iobuf.advance buf 1
  Iobuf.Poke.int32_le buf value;
  Iobuf.advance buf 4
;;

(** Emits a 'sub' instruction. *)
val sub_rm32_imm16 : (_, _) t -> Reg32 -> int16 -> unit
let sub_rm32_imm16 buf reg value =
  Iobuf.Poke.uint8 buf 129;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (reg + 5);
  Iobuf.advance buf 1
  Iobuf.Poke.int16_le buf value;
  Iobuf.advance buf 2
;;

(** Emits a 'sub' instruction. *)
val sub_rm32_imm32 : (_, _) t -> Reg32 -> int32 -> unit
let sub_rm32_imm32 buf reg value =
  Iobuf.Poke.uint8 buf 129;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (reg + 5);
  Iobuf.advance buf 1
  Iobuf.Poke.int32_le buf value;
  Iobuf.advance buf 4
;;

(** Emits a 'xor' instruction. *)
val xor_rm16_imm16 : (_, _) t -> Reg16 -> int16 -> unit
let xor_rm16_imm16 buf reg value =
  Iobuf.Poke.uint8 buf 102;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf 129;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (reg + 6);
  Iobuf.advance buf 1
  Iobuf.Poke.int16_le buf value;
  Iobuf.advance buf 2
;;

(** Emits a 'xor' instruction. *)
val xor_rm16_imm32 : (_, _) t -> Reg16 -> int32 -> unit
let xor_rm16_imm32 buf reg value =
  Iobuf.Poke.uint8 buf 102;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf 129;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (reg + 6);
  Iobuf.advance buf 1
  Iobuf.Poke.int32_le buf value;
  Iobuf.advance buf 4
;;

(** Emits a 'xor' instruction. *)
val xor_rm32_imm16 : (_, _) t -> Reg32 -> int16 -> unit
let xor_rm32_imm16 buf reg value =
  Iobuf.Poke.uint8 buf 129;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (reg + 6);
  Iobuf.advance buf 1
  Iobuf.Poke.int16_le buf value;
  Iobuf.advance buf 2
;;

(** Emits a 'xor' instruction. *)
val xor_rm32_imm32 : (_, _) t -> Reg32 -> int32 -> unit
let xor_rm32_imm32 buf reg value =
  Iobuf.Poke.uint8 buf 129;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (reg + 6);
  Iobuf.advance buf 1
  Iobuf.Poke.int32_le buf value;
  Iobuf.advance buf 4
;;

(** Emits a 'cmp' instruction. *)
val cmp_rm16_imm16 : (_, _) t -> Reg16 -> int16 -> unit
let cmp_rm16_imm16 buf reg value =
  Iobuf.Poke.uint8 buf 102;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf 129;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (reg + 7);
  Iobuf.advance buf 1
  Iobuf.Poke.int16_le buf value;
  Iobuf.advance buf 2
;;

(** Emits a 'cmp' instruction. *)
val cmp_rm16_imm32 : (_, _) t -> Reg16 -> int32 -> unit
let cmp_rm16_imm32 buf reg value =
  Iobuf.Poke.uint8 buf 102;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf 129;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (reg + 7);
  Iobuf.advance buf 1
  Iobuf.Poke.int32_le buf value;
  Iobuf.advance buf 4
;;

(** Emits a 'cmp' instruction. *)
val cmp_rm32_imm16 : (_, _) t -> Reg32 -> int16 -> unit
let cmp_rm32_imm16 buf reg value =
  Iobuf.Poke.uint8 buf 129;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (reg + 7);
  Iobuf.advance buf 1
  Iobuf.Poke.int16_le buf value;
  Iobuf.advance buf 2
;;

(** Emits a 'cmp' instruction. *)
val cmp_rm32_imm32 : (_, _) t -> Reg32 -> int32 -> unit
let cmp_rm32_imm32 buf reg value =
  Iobuf.Poke.uint8 buf 129;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (reg + 7);
  Iobuf.advance buf 1
  Iobuf.Poke.int32_le buf value;
  Iobuf.advance buf 4
;;

(** Emits an 'add' instruction. *)
val add_rm16_imm8 : (_, _) t -> Reg16 -> int8 -> unit
let add_rm16_imm8 buf reg value =
  Iobuf.Poke.uint8 buf 102;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf 131;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (reg + 0);
  Iobuf.advance buf 1
  Iobuf.Poke.int8 buf value;
  Iobuf.advance buf 1
;;

(** Emits an 'add' instruction. *)
val add_rm32_imm8 : (_, _) t -> Reg32 -> int8 -> unit
let add_rm32_imm8 buf reg value =
  Iobuf.Poke.uint8 buf 131;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (reg + 0);
  Iobuf.advance buf 1
  Iobuf.Poke.int8 buf value;
  Iobuf.advance buf 1
;;

(** Emits an 'or' instruction. *)
val or_rm16_imm8 : (_, _) t -> Reg16 -> int8 -> unit
let or_rm16_imm8 buf reg value =
  Iobuf.Poke.uint8 buf 102;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf 131;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (reg + 1);
  Iobuf.advance buf 1
  Iobuf.Poke.int8 buf value;
  Iobuf.advance buf 1
;;

(** Emits an 'or' instruction. *)
val or_rm32_imm8 : (_, _) t -> Reg32 -> int8 -> unit
let or_rm32_imm8 buf reg value =
  Iobuf.Poke.uint8 buf 131;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (reg + 1);
  Iobuf.advance buf 1
  Iobuf.Poke.int8 buf value;
  Iobuf.advance buf 1
;;

(** Emits an 'adc' instruction. *)
val adc_rm16_imm8 : (_, _) t -> Reg16 -> int8 -> unit
let adc_rm16_imm8 buf reg value =
  Iobuf.Poke.uint8 buf 102;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf 131;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (reg + 2);
  Iobuf.advance buf 1
  Iobuf.Poke.int8 buf value;
  Iobuf.advance buf 1
;;

(** Emits an 'adc' instruction. *)
val adc_rm32_imm8 : (_, _) t -> Reg32 -> int8 -> unit
let adc_rm32_imm8 buf reg value =
  Iobuf.Poke.uint8 buf 131;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (reg + 2);
  Iobuf.advance buf 1
  Iobuf.Poke.int8 buf value;
  Iobuf.advance buf 1
;;

(** Emits a 'sbb' instruction. *)
val sbb_rm16_imm8 : (_, _) t -> Reg16 -> int8 -> unit
let sbb_rm16_imm8 buf reg value =
  Iobuf.Poke.uint8 buf 102;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf 131;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (reg + 3);
  Iobuf.advance buf 1
  Iobuf.Poke.int8 buf value;
  Iobuf.advance buf 1
;;

(** Emits a 'sbb' instruction. *)
val sbb_rm32_imm8 : (_, _) t -> Reg32 -> int8 -> unit
let sbb_rm32_imm8 buf reg value =
  Iobuf.Poke.uint8 buf 131;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (reg + 3);
  Iobuf.advance buf 1
  Iobuf.Poke.int8 buf value;
  Iobuf.advance buf 1
;;

(** Emits an 'and' instruction. *)
val and_rm16_imm8 : (_, _) t -> Reg16 -> int8 -> unit
let and_rm16_imm8 buf reg value =
  Iobuf.Poke.uint8 buf 102;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf 131;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (reg + 4);
  Iobuf.advance buf 1
  Iobuf.Poke.int8 buf value;
  Iobuf.advance buf 1
;;

(** Emits an 'and' instruction. *)
val and_rm32_imm8 : (_, _) t -> Reg32 -> int8 -> unit
let and_rm32_imm8 buf reg value =
  Iobuf.Poke.uint8 buf 131;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (reg + 4);
  Iobuf.advance buf 1
  Iobuf.Poke.int8 buf value;
  Iobuf.advance buf 1
;;

(** Emits a 'sub' instruction. *)
val sub_rm16_imm8 : (_, _) t -> Reg16 -> int8 -> unit
let sub_rm16_imm8 buf reg value =
  Iobuf.Poke.uint8 buf 102;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf 131;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (reg + 5);
  Iobuf.advance buf 1
  Iobuf.Poke.int8 buf value;
  Iobuf.advance buf 1
;;

(** Emits a 'sub' instruction. *)
val sub_rm32_imm8 : (_, _) t -> Reg32 -> int8 -> unit
let sub_rm32_imm8 buf reg value =
  Iobuf.Poke.uint8 buf 131;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (reg + 5);
  Iobuf.advance buf 1
  Iobuf.Poke.int8 buf value;
  Iobuf.advance buf 1
;;

(** Emits a 'xor' instruction. *)
val xor_rm16_imm8 : (_, _) t -> Reg16 -> int8 -> unit
let xor_rm16_imm8 buf reg value =
  Iobuf.Poke.uint8 buf 102;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf 131;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (reg + 6);
  Iobuf.advance buf 1
  Iobuf.Poke.int8 buf value;
  Iobuf.advance buf 1
;;

(** Emits a 'xor' instruction. *)
val xor_rm32_imm8 : (_, _) t -> Reg32 -> int8 -> unit
let xor_rm32_imm8 buf reg value =
  Iobuf.Poke.uint8 buf 131;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (reg + 6);
  Iobuf.advance buf 1
  Iobuf.Poke.int8 buf value;
  Iobuf.advance buf 1
;;

(** Emits a 'cmp' instruction. *)
val cmp_rm16_imm8 : (_, _) t -> Reg16 -> int8 -> unit
let cmp_rm16_imm8 buf reg value =
  Iobuf.Poke.uint8 buf 102;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf 131;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (reg + 7);
  Iobuf.advance buf 1
  Iobuf.Poke.int8 buf value;
  Iobuf.advance buf 1
;;

(** Emits a 'cmp' instruction. *)
val cmp_rm32_imm8 : (_, _) t -> Reg32 -> int8 -> unit
let cmp_rm32_imm8 buf reg value =
  Iobuf.Poke.uint8 buf 131;
  Iobuf.advance buf 1
  Iobuf.Poke.uint8 buf (reg + 7);
  Iobuf.advance buf 1
  Iobuf.Poke.int8 buf value;
  Iobuf.advance buf 1
;;

