open Core

(** A Mips register. *)
type Reg = uint8
module Reg
  let zero = Reg 0 ;;
  let at = Reg 1 ;;
  let v0 = Reg 2 ;;
  let v1 = Reg 3 ;;
  let a0 = Reg 4 ;;
  let a1 = Reg 5 ;;
  let a2 = Reg 6 ;;
  let a3 = Reg 7 ;;
  let t0 = Reg 8 ;;
  let t1 = Reg 9 ;;
  let t2 = Reg 10 ;;
  let t3 = Reg 11 ;;
  let t4 = Reg 12 ;;
  let t5 = Reg 13 ;;
  let t6 = Reg 14 ;;
  let t7 = Reg 15 ;;
  let s0 = Reg 16 ;;
  let s1 = Reg 17 ;;
  let s2 = Reg 18 ;;
  let s3 = Reg 19 ;;
  let s4 = Reg 20 ;;
  let s5 = Reg 21 ;;
  let s6 = Reg 22 ;;
  let s7 = Reg 23 ;;
  let t8 = Reg 24 ;;
  let t9 = Reg 25 ;;
  let k0 = Reg 26 ;;
  let k1 = Reg 27 ;;
  let gp = Reg 28 ;;
  let sp = Reg 29 ;;
  let fp = Reg 30 ;;
  let ra = Reg 31 ;;
;;


(** Emits a 'sll' instruction. *)
val sll : (_, _) t -> Reg -> Reg -> Reg -> uint8 -> unit
let sll buf rd rs rt shift =
  Iobuf.Poke.uint32_le buf ((((0 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
  Iobuf.advance buf 4
;;

(** Emits a 'movci' instruction. *)
val movci : (_, _) t -> Reg -> Reg -> Reg -> uint8 -> unit
let movci buf rd rs rt shift =
  Iobuf.Poke.uint32_le buf ((((1 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
  Iobuf.advance buf 4
;;

(** Emits a 'srl' instruction. *)
val srl : (_, _) t -> Reg -> Reg -> Reg -> uint8 -> unit
let srl buf rd rs rt shift =
  Iobuf.Poke.uint32_le buf ((((2 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
  Iobuf.advance buf 4
;;

(** Emits a 'sra' instruction. *)
val sra : (_, _) t -> Reg -> Reg -> Reg -> uint8 -> unit
let sra buf rd rs rt shift =
  Iobuf.Poke.uint32_le buf ((((3 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
  Iobuf.advance buf 4
;;

(** Emits a 'sllv' instruction. *)
val sllv_r : (_, _) t -> Reg -> Reg -> Reg -> uint8 -> unit
let sllv_r buf rd rs rt shift =
  Iobuf.Poke.uint32_le buf ((((4 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
  Iobuf.advance buf 4
;;

(** Emits a 'srlv' instruction. *)
val srlv : (_, _) t -> Reg -> Reg -> Reg -> uint8 -> unit
let srlv buf rd rs rt shift =
  Iobuf.Poke.uint32_le buf ((((6 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
  Iobuf.advance buf 4
;;

(** Emits a 'srav' instruction. *)
val srav : (_, _) t -> Reg -> Reg -> Reg -> uint8 -> unit
let srav buf rd rs rt shift =
  Iobuf.Poke.uint32_le buf ((((7 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
  Iobuf.advance buf 4
;;

(** Emits a 'jr' instruction. *)
val jr : (_, _) t -> Reg -> Reg -> Reg -> uint8 -> unit
let jr buf rd rs rt shift =
  Iobuf.Poke.uint32_le buf ((((8 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
  Iobuf.advance buf 4
;;

(** Emits a 'jalr' instruction. *)
val jalr_r : (_, _) t -> Reg -> Reg -> Reg -> uint8 -> unit
let jalr_r buf rd rs rt shift =
  Iobuf.Poke.uint32_le buf ((((9 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
  Iobuf.advance buf 4
;;

(** Emits a 'movz' instruction. *)
val movz : (_, _) t -> Reg -> Reg -> Reg -> uint8 -> unit
let movz buf rd rs rt shift =
  Iobuf.Poke.uint32_le buf ((((10 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
  Iobuf.advance buf 4
;;

(** Emits a 'movn' instruction. *)
val movn : (_, _) t -> Reg -> Reg -> Reg -> uint8 -> unit
let movn buf rd rs rt shift =
  Iobuf.Poke.uint32_le buf ((((11 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
  Iobuf.advance buf 4
;;

(** Emits a 'syscall' instruction. *)
val syscall : (_, _) t -> Reg -> Reg -> Reg -> uint8 -> unit
let syscall buf rd rs rt shift =
  Iobuf.Poke.uint32_le buf ((((12 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
  Iobuf.advance buf 4
;;

(** Emits a 'breakpoint' instruction. *)
val breakpoint : (_, _) t -> Reg -> Reg -> Reg -> uint8 -> unit
let breakpoint buf rd rs rt shift =
  Iobuf.Poke.uint32_le buf ((((13 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
  Iobuf.advance buf 4
;;

(** Emits a 'sync' instruction. *)
val sync : (_, _) t -> Reg -> Reg -> Reg -> uint8 -> unit
let sync buf rd rs rt shift =
  Iobuf.Poke.uint32_le buf ((((15 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
  Iobuf.advance buf 4
;;

(** Emits a 'mfhi' instruction. *)
val mfhi : (_, _) t -> Reg -> Reg -> Reg -> uint8 -> unit
let mfhi buf rd rs rt shift =
  Iobuf.Poke.uint32_le buf ((((16 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
  Iobuf.advance buf 4
;;

(** Emits a 'mthi' instruction. *)
val mthi : (_, _) t -> Reg -> Reg -> Reg -> uint8 -> unit
let mthi buf rd rs rt shift =
  Iobuf.Poke.uint32_le buf ((((17 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
  Iobuf.advance buf 4
;;

(** Emits a 'mflo' instruction. *)
val mflo : (_, _) t -> Reg -> Reg -> Reg -> uint8 -> unit
let mflo buf rd rs rt shift =
  Iobuf.Poke.uint32_le buf ((((18 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
  Iobuf.advance buf 4
;;

(** Emits a 'dsllv' instruction. *)
val dsllv_r : (_, _) t -> Reg -> Reg -> Reg -> uint8 -> unit
let dsllv_r buf rd rs rt shift =
  Iobuf.Poke.uint32_le buf ((((20 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
  Iobuf.advance buf 4
;;

(** Emits a 'dsrlv' instruction. *)
val dsrlv : (_, _) t -> Reg -> Reg -> Reg -> uint8 -> unit
let dsrlv buf rd rs rt shift =
  Iobuf.Poke.uint32_le buf ((((22 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
  Iobuf.advance buf 4
;;

(** Emits a 'dsrav' instruction. *)
val dsrav : (_, _) t -> Reg -> Reg -> Reg -> uint8 -> unit
let dsrav buf rd rs rt shift =
  Iobuf.Poke.uint32_le buf ((((23 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
  Iobuf.advance buf 4
;;

(** Emits a 'mult' instruction. *)
val mult : (_, _) t -> Reg -> Reg -> Reg -> uint8 -> unit
let mult buf rd rs rt shift =
  Iobuf.Poke.uint32_le buf ((((24 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
  Iobuf.advance buf 4
;;

(** Emits a 'multu' instruction. *)
val multu : (_, _) t -> Reg -> Reg -> Reg -> uint8 -> unit
let multu buf rd rs rt shift =
  Iobuf.Poke.uint32_le buf ((((25 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
  Iobuf.advance buf 4
;;

(** Emits a 'div' instruction. *)
val div : (_, _) t -> Reg -> Reg -> Reg -> uint8 -> unit
let div buf rd rs rt shift =
  Iobuf.Poke.uint32_le buf ((((26 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
  Iobuf.advance buf 4
;;

(** Emits a 'divu' instruction. *)
val divu : (_, _) t -> Reg -> Reg -> Reg -> uint8 -> unit
let divu buf rd rs rt shift =
  Iobuf.Poke.uint32_le buf ((((27 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
  Iobuf.advance buf 4
;;

(** Emits a 'dmult' instruction. *)
val dmult : (_, _) t -> Reg -> Reg -> Reg -> uint8 -> unit
let dmult buf rd rs rt shift =
  Iobuf.Poke.uint32_le buf ((((28 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
  Iobuf.advance buf 4
;;

(** Emits a 'dmultu' instruction. *)
val dmultu : (_, _) t -> Reg -> Reg -> Reg -> uint8 -> unit
let dmultu buf rd rs rt shift =
  Iobuf.Poke.uint32_le buf ((((29 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
  Iobuf.advance buf 4
;;

(** Emits a 'ddiv' instruction. *)
val ddiv : (_, _) t -> Reg -> Reg -> Reg -> uint8 -> unit
let ddiv buf rd rs rt shift =
  Iobuf.Poke.uint32_le buf ((((30 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
  Iobuf.advance buf 4
;;

(** Emits a 'ddivu' instruction. *)
val ddivu : (_, _) t -> Reg -> Reg -> Reg -> uint8 -> unit
let ddivu buf rd rs rt shift =
  Iobuf.Poke.uint32_le buf ((((31 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
  Iobuf.advance buf 4
;;

(** Emits an 'add' instruction. *)
val add : (_, _) t -> Reg -> Reg -> Reg -> uint8 -> unit
let add buf rd rs rt shift =
  Iobuf.Poke.uint32_le buf ((((32 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
  Iobuf.advance buf 4
;;

(** Emits an 'addu' instruction. *)
val addu : (_, _) t -> Reg -> Reg -> Reg -> uint8 -> unit
let addu buf rd rs rt shift =
  Iobuf.Poke.uint32_le buf ((((33 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
  Iobuf.advance buf 4
;;

(** Emits a 'sub' instruction. *)
val sub : (_, _) t -> Reg -> Reg -> Reg -> uint8 -> unit
let sub buf rd rs rt shift =
  Iobuf.Poke.uint32_le buf ((((34 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
  Iobuf.advance buf 4
;;

(** Emits a 'subu' instruction. *)
val subu : (_, _) t -> Reg -> Reg -> Reg -> uint8 -> unit
let subu buf rd rs rt shift =
  Iobuf.Poke.uint32_le buf ((((35 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
  Iobuf.advance buf 4
;;

(** Emits an 'and' instruction. *)
val and : (_, _) t -> Reg -> Reg -> Reg -> uint8 -> unit
let and buf rd rs rt shift =
  Iobuf.Poke.uint32_le buf ((((36 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
  Iobuf.advance buf 4
;;

(** Emits an 'or' instruction. *)
val or : (_, _) t -> Reg -> Reg -> Reg -> uint8 -> unit
let or buf rd rs rt shift =
  Iobuf.Poke.uint32_le buf ((((37 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
  Iobuf.advance buf 4
;;

(** Emits a 'xor' instruction. *)
val xor : (_, _) t -> Reg -> Reg -> Reg -> uint8 -> unit
let xor buf rd rs rt shift =
  Iobuf.Poke.uint32_le buf ((((38 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
  Iobuf.advance buf 4
;;

(** Emits a 'nor' instruction. *)
val nor : (_, _) t -> Reg -> Reg -> Reg -> uint8 -> unit
let nor buf rd rs rt shift =
  Iobuf.Poke.uint32_le buf ((((39 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
  Iobuf.advance buf 4
;;

(** Emits a 'slt' instruction. *)
val slt : (_, _) t -> Reg -> Reg -> Reg -> uint8 -> unit
let slt buf rd rs rt shift =
  Iobuf.Poke.uint32_le buf ((((42 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
  Iobuf.advance buf 4
;;

(** Emits a 'sltu' instruction. *)
val sltu : (_, _) t -> Reg -> Reg -> Reg -> uint8 -> unit
let sltu buf rd rs rt shift =
  Iobuf.Poke.uint32_le buf ((((43 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
  Iobuf.advance buf 4
;;

(** Emits a 'dadd' instruction. *)
val dadd : (_, _) t -> Reg -> Reg -> Reg -> uint8 -> unit
let dadd buf rd rs rt shift =
  Iobuf.Poke.uint32_le buf ((((44 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
  Iobuf.advance buf 4
;;

(** Emits a 'daddu' instruction. *)
val daddu : (_, _) t -> Reg -> Reg -> Reg -> uint8 -> unit
let daddu buf rd rs rt shift =
  Iobuf.Poke.uint32_le buf ((((45 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
  Iobuf.advance buf 4
;;

(** Emits a 'dsub' instruction. *)
val dsub : (_, _) t -> Reg -> Reg -> Reg -> uint8 -> unit
let dsub buf rd rs rt shift =
  Iobuf.Poke.uint32_le buf ((((46 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
  Iobuf.advance buf 4
;;

(** Emits a 'dsubu' instruction. *)
val dsubu : (_, _) t -> Reg -> Reg -> Reg -> uint8 -> unit
let dsubu buf rd rs rt shift =
  Iobuf.Poke.uint32_le buf ((((47 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
  Iobuf.advance buf 4
;;

(** Emits a 'tge' instruction. *)
val tge : (_, _) t -> Reg -> Reg -> Reg -> uint8 -> unit
let tge buf rd rs rt shift =
  Iobuf.Poke.uint32_le buf ((((48 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
  Iobuf.advance buf 4
;;

(** Emits a 'tgeu' instruction. *)
val tgeu : (_, _) t -> Reg -> Reg -> Reg -> uint8 -> unit
let tgeu buf rd rs rt shift =
  Iobuf.Poke.uint32_le buf ((((49 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
  Iobuf.advance buf 4
;;

(** Emits a 'tlt' instruction. *)
val tlt : (_, _) t -> Reg -> Reg -> Reg -> uint8 -> unit
let tlt buf rd rs rt shift =
  Iobuf.Poke.uint32_le buf ((((50 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
  Iobuf.advance buf 4
;;

(** Emits a 'tltu' instruction. *)
val tltu : (_, _) t -> Reg -> Reg -> Reg -> uint8 -> unit
let tltu buf rd rs rt shift =
  Iobuf.Poke.uint32_le buf ((((51 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
  Iobuf.advance buf 4
;;

(** Emits a 'teq' instruction. *)
val teq : (_, _) t -> Reg -> Reg -> Reg -> uint8 -> unit
let teq buf rd rs rt shift =
  Iobuf.Poke.uint32_le buf ((((52 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
  Iobuf.advance buf 4
;;

(** Emits a 'tne' instruction. *)
val tne : (_, _) t -> Reg -> Reg -> Reg -> uint8 -> unit
let tne buf rd rs rt shift =
  Iobuf.Poke.uint32_le buf ((((54 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
  Iobuf.advance buf 4
;;

(** Emits a 'dsll' instruction. *)
val dsll : (_, _) t -> Reg -> Reg -> Reg -> uint8 -> unit
let dsll buf rd rs rt shift =
  Iobuf.Poke.uint32_le buf ((((56 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
  Iobuf.advance buf 4
;;

(** Emits a 'dslr' instruction. *)
val dslr : (_, _) t -> Reg -> Reg -> Reg -> uint8 -> unit
let dslr buf rd rs rt shift =
  Iobuf.Poke.uint32_le buf ((((58 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
  Iobuf.advance buf 4
;;

(** Emits a 'dsra' instruction. *)
val dsra : (_, _) t -> Reg -> Reg -> Reg -> uint8 -> unit
let dsra buf rd rs rt shift =
  Iobuf.Poke.uint32_le buf ((((59 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
  Iobuf.advance buf 4
;;

(** Emits a 'mhc0' instruction. *)
val mhc0 : (_, _) t -> Reg -> Reg -> Reg -> uint8 -> unit
let mhc0 buf rd rs rt shift =
  Iobuf.Poke.uint32_le buf ((((1073741824 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((rd & 31) << 11)) | ((shift & 31) << 6));
  Iobuf.advance buf 4
;;

(** Emits a 'btlz' instruction. *)
val btlz : (_, _) t -> Reg -> uint16 -> unit
let btlz buf rs target =
  Iobuf.Poke.uint32_le buf ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535));
  Iobuf.advance buf 4
;;

(** Emits a 'bgez' instruction. *)
val bgez : (_, _) t -> Reg -> uint16 -> unit
let bgez buf rs target =
  Iobuf.Poke.uint32_le buf ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535));
  Iobuf.advance buf 4
;;

(** Emits a 'bltzl' instruction. *)
val bltzl : (_, _) t -> Reg -> uint16 -> unit
let bltzl buf rs target =
  Iobuf.Poke.uint32_le buf ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535));
  Iobuf.advance buf 4
;;

(** Emits a 'bgezl' instruction. *)
val bgezl : (_, _) t -> Reg -> uint16 -> unit
let bgezl buf rs target =
  Iobuf.Poke.uint32_le buf ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535));
  Iobuf.advance buf 4
;;

(** Emits a 'sllv' instruction. *)
val sllv_ri : (_, _) t -> Reg -> uint16 -> unit
let sllv_ri buf rs target =
  Iobuf.Poke.uint32_le buf ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535));
  Iobuf.advance buf 4
;;

(** Emits a 'tgei' instruction. *)
val tgei : (_, _) t -> Reg -> uint16 -> unit
let tgei buf rs target =
  Iobuf.Poke.uint32_le buf ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535));
  Iobuf.advance buf 4
;;

(** Emits a 'jalr' instruction. *)
val jalr_ri : (_, _) t -> Reg -> uint16 -> unit
let jalr_ri buf rs target =
  Iobuf.Poke.uint32_le buf ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535));
  Iobuf.advance buf 4
;;

(** Emits a 'tlti' instruction. *)
val tlti : (_, _) t -> Reg -> uint16 -> unit
let tlti buf rs target =
  Iobuf.Poke.uint32_le buf ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535));
  Iobuf.advance buf 4
;;

(** Emits a 'tltiu' instruction. *)
val tltiu : (_, _) t -> Reg -> uint16 -> unit
let tltiu buf rs target =
  Iobuf.Poke.uint32_le buf ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535));
  Iobuf.advance buf 4
;;

(** Emits a 'teqi' instruction. *)
val teqi : (_, _) t -> Reg -> uint16 -> unit
let teqi buf rs target =
  Iobuf.Poke.uint32_le buf ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535));
  Iobuf.advance buf 4
;;

(** Emits a 'tnei' instruction. *)
val tnei : (_, _) t -> Reg -> uint16 -> unit
let tnei buf rs target =
  Iobuf.Poke.uint32_le buf ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535));
  Iobuf.advance buf 4
;;

(** Emits a 'bltzal' instruction. *)
val bltzal : (_, _) t -> Reg -> uint16 -> unit
let bltzal buf rs target =
  Iobuf.Poke.uint32_le buf ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535));
  Iobuf.advance buf 4
;;

(** Emits a 'bgezal' instruction. *)
val bgezal : (_, _) t -> Reg -> uint16 -> unit
let bgezal buf rs target =
  Iobuf.Poke.uint32_le buf ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535));
  Iobuf.advance buf 4
;;

(** Emits a 'bltzall' instruction. *)
val bltzall : (_, _) t -> Reg -> uint16 -> unit
let bltzall buf rs target =
  Iobuf.Poke.uint32_le buf ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535));
  Iobuf.advance buf 4
;;

(** Emits a 'bgezall' instruction. *)
val bgezall : (_, _) t -> Reg -> uint16 -> unit
let bgezall buf rs target =
  Iobuf.Poke.uint32_le buf ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535));
  Iobuf.advance buf 4
;;

(** Emits a 'dsllv' instruction. *)
val dsllv_ri : (_, _) t -> Reg -> uint16 -> unit
let dsllv_ri buf rs target =
  Iobuf.Poke.uint32_le buf ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535));
  Iobuf.advance buf 4
;;

(** Emits a 'synci' instruction. *)
val synci : (_, _) t -> Reg -> uint16 -> unit
let synci buf rs target =
  Iobuf.Poke.uint32_le buf ((67108864 | ((rs & 31) << 16)) | ((target >> 2) & 65535));
  Iobuf.advance buf 4
;;

(** Emits an 'addi' instruction. *)
val addi : (_, _) t -> Reg -> Reg -> uint16 -> unit
let addi buf rs rt imm =
  Iobuf.Poke.uint32_le buf (((536870912 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535));
  Iobuf.advance buf 4
;;

(** Emits an 'addiu' instruction. *)
val addiu : (_, _) t -> Reg -> Reg -> uint16 -> unit
let addiu buf rs rt imm =
  Iobuf.Poke.uint32_le buf (((603979776 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535));
  Iobuf.advance buf 4
;;

(** Emits an 'andi' instruction. *)
val andi : (_, _) t -> Reg -> Reg -> uint16 -> unit
let andi buf rs rt imm =
  Iobuf.Poke.uint32_le buf (((805306368 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535));
  Iobuf.advance buf 4
;;

(** Emits a 'beq' instruction. *)
val beq : (_, _) t -> Reg -> Reg -> uint16 -> unit
let beq buf rs rt imm =
  Iobuf.Poke.uint32_le buf (((268435456 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((imm & 65535) >> 2));
  Iobuf.advance buf 4
;;

(** Emits a 'blez' instruction. *)
val blez : (_, _) t -> Reg -> Reg -> uint16 -> unit
let blez buf rs rt imm =
  Iobuf.Poke.uint32_le buf (((402653184 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((imm & 65535) >> 2));
  Iobuf.advance buf 4
;;

(** Emits a 'bne' instruction. *)
val bne : (_, _) t -> Reg -> Reg -> uint16 -> unit
let bne buf rs rt imm =
  Iobuf.Poke.uint32_le buf (((335544320 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | ((imm & 65535) >> 2));
  Iobuf.advance buf 4
;;

(** Emits a 'lw' instruction. *)
val lw : (_, _) t -> Reg -> Reg -> uint16 -> unit
let lw buf rs rt imm =
  Iobuf.Poke.uint32_le buf (((2348810240 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535));
  Iobuf.advance buf 4
;;

(** Emits a 'lbu' instruction. *)
val lbu : (_, _) t -> Reg -> Reg -> uint16 -> unit
let lbu buf rs rt imm =
  Iobuf.Poke.uint32_le buf (((2415919104 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535));
  Iobuf.advance buf 4
;;

(** Emits a 'lhu' instruction. *)
val lhu : (_, _) t -> Reg -> Reg -> uint16 -> unit
let lhu buf rs rt imm =
  Iobuf.Poke.uint32_le buf (((2483027968 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535));
  Iobuf.advance buf 4
;;

(** Emits a 'lui' instruction. *)
val lui : (_, _) t -> Reg -> Reg -> uint16 -> unit
let lui buf rs rt imm =
  Iobuf.Poke.uint32_le buf (((1006632960 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535));
  Iobuf.advance buf 4
;;

(** Emits an 'ori' instruction. *)
val ori : (_, _) t -> Reg -> Reg -> uint16 -> unit
let ori buf rs rt imm =
  Iobuf.Poke.uint32_le buf (((872415232 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535));
  Iobuf.advance buf 4
;;

(** Emits a 'sb' instruction. *)
val sb : (_, _) t -> Reg -> Reg -> uint16 -> unit
let sb buf rs rt imm =
  Iobuf.Poke.uint32_le buf (((2684354560 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535));
  Iobuf.advance buf 4
;;

(** Emits a 'sh' instruction. *)
val sh : (_, _) t -> Reg -> Reg -> uint16 -> unit
let sh buf rs rt imm =
  Iobuf.Poke.uint32_le buf (((2751463424 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535));
  Iobuf.advance buf 4
;;

(** Emits a 'slti' instruction. *)
val slti : (_, _) t -> Reg -> Reg -> uint16 -> unit
let slti buf rs rt imm =
  Iobuf.Poke.uint32_le buf (((671088640 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535));
  Iobuf.advance buf 4
;;

(** Emits a 'sltiu' instruction. *)
val sltiu : (_, _) t -> Reg -> Reg -> uint16 -> unit
let sltiu buf rs rt imm =
  Iobuf.Poke.uint32_le buf (((738197504 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535));
  Iobuf.advance buf 4
;;

(** Emits a 'sw' instruction. *)
val sw : (_, _) t -> Reg -> Reg -> uint16 -> unit
let sw buf rs rt imm =
  Iobuf.Poke.uint32_le buf (((2885681152 | ((rs & 31) << 21)) | ((rt & 31) << 16)) | (imm & 65535));
  Iobuf.advance buf 4
;;

(** Emits a 'j' instruction. *)
val j : (_, _) t -> uint32 -> unit
let j buf address =
  Iobuf.Poke.uint32_le buf (134217728 | ((address >> 2) & 67108863));
  Iobuf.advance buf 4
;;

(** Emits a 'jal' instruction. *)
val jal : (_, _) t -> uint32 -> unit
let jal buf address =
  Iobuf.Poke.uint32_le buf (201326592 | ((address >> 2) & 67108863));
  Iobuf.advance buf 4
;;

