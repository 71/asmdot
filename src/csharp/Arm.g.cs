using System;
using System.Runtime.InteropServices;

namespace Asm.Net
{
    partial class Arm
    {
        /// <summary>Emits an <c>adc</c> instruction.</summary>
        public static void adc(ref IntPtr buffer, Condition cond, bool i, bool s, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((((1280 | cond) | (i << 6)) | (s << 11)) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an <c>add</c> instruction.</summary>
        public static void add(ref IntPtr buffer, Condition cond, bool i, bool s, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((((256 | cond) | (i << 6)) | (s << 11)) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an <c>and</c> instruction.</summary>
        public static void and(ref IntPtr buffer, Condition cond, bool i, bool s, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((((0 | cond) | (i << 6)) | (s << 11)) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an <c>eor</c> instruction.</summary>
        public static void eor(ref IntPtr buffer, Condition cond, bool i, bool s, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((((1024 | cond) | (i << 6)) | (s << 11)) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an <c>orr</c> instruction.</summary>
        public static void orr(ref IntPtr buffer, Condition cond, bool i, bool s, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((((384 | cond) | (i << 6)) | (s << 11)) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>rsb</c> instruction.</summary>
        public static void rsb(ref IntPtr buffer, Condition cond, bool i, bool s, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((((1536 | cond) | (i << 6)) | (s << 11)) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>rsc</c> instruction.</summary>
        public static void rsc(ref IntPtr buffer, Condition cond, bool i, bool s, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((((1792 | cond) | (i << 6)) | (s << 11)) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>sbc</c> instruction.</summary>
        public static void sbc(ref IntPtr buffer, Condition cond, bool i, bool s, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((((768 | cond) | (i << 6)) | (s << 11)) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>sub</c> instruction.</summary>
        public static void sub(ref IntPtr buffer, Condition cond, bool i, bool s, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((((512 | cond) | (i << 6)) | (s << 11)) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>bkpt</c> instruction.</summary>
        public static void bkpt(ref IntPtr buffer)
        {
            *(uint*)(*buf) = 234882183;
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>b</c> instruction.</summary>
        public static void b(ref IntPtr buffer, Condition cond)
        {
            *(uint*)(*buf) = (80 | cond);
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>bic</c> instruction.</summary>
        public static void bic(ref IntPtr buffer, Condition cond, bool i, bool s, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((((896 | cond) | (i << 6)) | (s << 11)) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>blx</c> instruction.</summary>
        public static void blx(ref IntPtr buffer, Condition cond)
        {
            *(uint*)(*buf) = (218100864 | cond);
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>bx</c> instruction.</summary>
        public static void bx(ref IntPtr buffer, Condition cond)
        {
            *(uint*)(*buf) = (150992000 | cond);
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>bxj</c> instruction.</summary>
        public static void bxj(ref IntPtr buffer, Condition cond)
        {
            *(uint*)(*buf) = (83883136 | cond);
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>blxun</c> instruction.</summary>
        public static void blxun(ref IntPtr buffer)
        {
            *(uint*)(*buf) = 95;
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>cdp</c> instruction.</summary>
        public static void cdp(ref IntPtr buffer, Condition cond)
        {
            *(uint*)(*buf) = (112 | cond);
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>clz</c> instruction.</summary>
        public static void clz(ref IntPtr buffer, Condition cond, Reg rd)
        {
            *(uint*)(*buf) = ((150009472 | cond) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>cmn</c> instruction.</summary>
        public static void cmn(ref IntPtr buffer, Condition cond, bool i, Reg rn)
        {
            *(uint*)(*buf) = (((3712 | cond) | (i << 6)) | (rn << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>cmp</c> instruction.</summary>
        public static void cmp(ref IntPtr buffer, Condition cond, bool i, Reg rn)
        {
            *(uint*)(*buf) = (((2688 | cond) | (i << 6)) | (rn << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>cpy</c> instruction.</summary>
        public static void cpy(ref IntPtr buffer, Condition cond, Reg rd)
        {
            *(uint*)(*buf) = ((1408 | cond) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>cps</c> instruction.</summary>
        public static void cps(ref IntPtr buffer, Mode mode)
        {
            *(uint*)(*buf) = (16527 | (mode << 24));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>cpsie</c> instruction.</summary>
        public static void cpsie(ref IntPtr buffer, InterruptFlags iflags)
        {
            *(uint*)(*buf) = (4239 | (iflags << 20));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>cpsid</c> instruction.</summary>
        public static void cpsid(ref IntPtr buffer, InterruptFlags iflags)
        {
            *(uint*)(*buf) = (12431 | (iflags << 20));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>cpsie_mode</c> instruction.</summary>
        public static void cpsie_mode(ref IntPtr buffer, InterruptFlags iflags, Mode mode)
        {
            *(uint*)(*buf) = ((20623 | (iflags << 20)) | (mode << 24));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>cpsid_mode</c> instruction.</summary>
        public static void cpsid_mode(ref IntPtr buffer, InterruptFlags iflags, Mode mode)
        {
            *(uint*)(*buf) = ((28815 | (iflags << 20)) | (mode << 24));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>ldc</c> instruction.</summary>
        public static void ldc(ref IntPtr buffer, Condition cond, bool write, Reg rn)
        {
            *(uint*)(*buf) = (((560 | cond) | (write << 8)) | (rn << 10));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>ldm1</c> instruction.</summary>
        public static void ldm1(ref IntPtr buffer, Condition cond, bool write, Reg rn)
        {
            *(uint*)(*buf) = (((528 | cond) | (write << 8)) | (rn << 10));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>ldm2</c> instruction.</summary>
        public static void ldm2(ref IntPtr buffer, Condition cond, Reg rn)
        {
            *(uint*)(*buf) = ((656 | cond) | (rn << 10));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>ldm3</c> instruction.</summary>
        public static void ldm3(ref IntPtr buffer, Condition cond, bool write, Reg rn)
        {
            *(uint*)(*buf) = (((17040 | cond) | (write << 8)) | (rn << 10));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>ldr</c> instruction.</summary>
        public static void ldr(ref IntPtr buffer, Condition cond, bool write, bool i, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((((544 | cond) | (write << 8)) | (i << 6)) | (rn << 10)) | (rd << 14));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>ldrb</c> instruction.</summary>
        public static void ldrb(ref IntPtr buffer, Condition cond, bool write, bool i, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((((672 | cond) | (write << 8)) | (i << 6)) | (rn << 10)) | (rd << 14));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>ldrbt</c> instruction.</summary>
        public static void ldrbt(ref IntPtr buffer, Condition cond, bool i, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = ((((1824 | cond) | (i << 6)) | (rn << 11)) | (rd << 15));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>ldrd</c> instruction.</summary>
        public static void ldrd(ref IntPtr buffer, Condition cond, bool write, bool i, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((((2883584 | cond) | (write << 8)) | (i << 7)) | (rn << 10)) | (rd << 14));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>ldrex</c> instruction.</summary>
        public static void ldrex(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((4193257856 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>ldrh</c> instruction.</summary>
        public static void ldrh(ref IntPtr buffer, Condition cond, bool write, bool i, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((((3408384 | cond) | (write << 8)) | (i << 7)) | (rn << 10)) | (rd << 14));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>ldrsb</c> instruction.</summary>
        public static void ldrsb(ref IntPtr buffer, Condition cond, bool write, bool i, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((((2884096 | cond) | (write << 8)) | (i << 7)) | (rn << 10)) | (rd << 14));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>ldrsh</c> instruction.</summary>
        public static void ldrsh(ref IntPtr buffer, Condition cond, bool write, bool i, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((((3932672 | cond) | (write << 8)) | (i << 7)) | (rn << 10)) | (rd << 14));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>ldrt</c> instruction.</summary>
        public static void ldrt(ref IntPtr buffer, Condition cond, bool i, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = ((((1568 | cond) | (i << 6)) | (rn << 11)) | (rd << 15));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>mcr</c> instruction.</summary>
        public static void mcr(ref IntPtr buffer, Condition cond, Reg rd)
        {
            *(uint*)(*buf) = ((131184 | cond) | (rd << 13));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>mcrr</c> instruction.</summary>
        public static void mcrr(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((560 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>mla</c> instruction.</summary>
        public static void mla(ref IntPtr buffer, Condition cond, bool s, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = ((((150995968 | cond) | (s << 11)) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>mov</c> instruction.</summary>
        public static void mov(ref IntPtr buffer, Condition cond, bool i, bool s, Reg rd)
        {
            *(uint*)(*buf) = ((((1408 | cond) | (i << 6)) | (s << 11)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>mrc</c> instruction.</summary>
        public static void mrc(ref IntPtr buffer, Condition cond, Reg rd)
        {
            *(uint*)(*buf) = ((131440 | cond) | (rd << 13));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>mrrc</c> instruction.</summary>
        public static void mrrc(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((2608 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>mrs</c> instruction.</summary>
        public static void mrs(ref IntPtr buffer, Condition cond, Reg rd)
        {
            *(uint*)(*buf) = ((61568 | cond) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>mul</c> instruction.</summary>
        public static void mul(ref IntPtr buffer, Condition cond, bool s, Reg rd)
        {
            *(uint*)(*buf) = (((150994944 | cond) | (s << 11)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>mvn</c> instruction.</summary>
        public static void mvn(ref IntPtr buffer, Condition cond, bool i, bool s, Reg rd)
        {
            *(uint*)(*buf) = ((((1920 | cond) | (i << 6)) | (s << 11)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>msr_imm</c> instruction.</summary>
        public static void msr_imm(ref IntPtr buffer, Condition cond, FieldMask fieldmask)
        {
            *(uint*)(*buf) = ((984256 | cond) | (fieldmask << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>msr_reg</c> instruction.</summary>
        public static void msr_reg(ref IntPtr buffer, Condition cond, FieldMask fieldmask)
        {
            *(uint*)(*buf) = ((984192 | cond) | (fieldmask << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>pkhbt</c> instruction.</summary>
        public static void pkhbt(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((134218080 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>pkhtb</c> instruction.</summary>
        public static void pkhtb(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((167772512 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>pld</c> instruction.</summary>
        public static void pld(ref IntPtr buffer, bool i, Reg rn)
        {
            *(uint*)(*buf) = ((492975 | (i << 6)) | (rn << 11));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>qadd</c> instruction.</summary>
        public static void qadd(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((167772288 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>qadd16</c> instruction.</summary>
        public static void qadd16(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((149947488 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>qadd8</c> instruction.</summary>
        public static void qadd8(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((166724704 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>qaddsubx</c> instruction.</summary>
        public static void qaddsubx(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((217056352 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>qdadd</c> instruction.</summary>
        public static void qdadd(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((167772800 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>qdsub</c> instruction.</summary>
        public static void qdsub(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((167773824 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>qsub</c> instruction.</summary>
        public static void qsub(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((167773312 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>qsub16</c> instruction.</summary>
        public static void qsub16(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((250610784 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>qsub8</c> instruction.</summary>
        public static void qsub8(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((267388000 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>qsubaddx</c> instruction.</summary>
        public static void qsubaddx(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((183501920 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>rev</c> instruction.</summary>
        public static void rev(ref IntPtr buffer, Condition cond, Reg rd)
        {
            *(uint*)(*buf) = ((217120096 | cond) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>rev16</c> instruction.</summary>
        public static void rev16(ref IntPtr buffer, Condition cond, Reg rd)
        {
            *(uint*)(*buf) = ((233897312 | cond) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>revsh</c> instruction.</summary>
        public static void revsh(ref IntPtr buffer, Condition cond, Reg rd)
        {
            *(uint*)(*buf) = ((233897824 | cond) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>rfe</c> instruction.</summary>
        public static void rfe(ref IntPtr buffer, bool write, Reg rn)
        {
            *(uint*)(*buf) = ((1311263 | (write << 8)) | (rn << 10));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>sadd16</c> instruction.</summary>
        public static void sadd16(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((149948512 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>sadd8</c> instruction.</summary>
        public static void sadd8(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((166725728 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>saddsubx</c> instruction.</summary>
        public static void saddsubx(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((217057376 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>sel</c> instruction.</summary>
        public static void sel(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((233832800 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>setendbe</c> instruction.</summary>
        public static void setendbe(ref IntPtr buffer)
        {
            *(uint*)(*buf) = 4227215;
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>setendle</c> instruction.</summary>
        public static void setendle(ref IntPtr buffer)
        {
            *(uint*)(*buf) = 32911;
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>shadd16</c> instruction.</summary>
        public static void shadd16(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((149949536 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>shadd8</c> instruction.</summary>
        public static void shadd8(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((166726752 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>shaddsubx</c> instruction.</summary>
        public static void shaddsubx(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((217058400 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>shsub16</c> instruction.</summary>
        public static void shsub16(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((250612832 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>shsub8</c> instruction.</summary>
        public static void shsub8(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((267390048 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>shsubaddx</c> instruction.</summary>
        public static void shsubaddx(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((183503968 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>smlabb</c> instruction.</summary>
        public static void smlabb(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((16777344 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>smlabt</c> instruction.</summary>
        public static void smlabt(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((83886208 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>smlatb</c> instruction.</summary>
        public static void smlatb(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((50331776 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>smlatt</c> instruction.</summary>
        public static void smlatt(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((117440640 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>smlad</c> instruction.</summary>
        public static void smlad(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((67109088 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>smlal</c> instruction.</summary>
        public static void smlal(ref IntPtr buffer, Condition cond, bool s)
        {
            *(uint*)(*buf) = ((150996736 | cond) | (s << 11));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>smlalbb</c> instruction.</summary>
        public static void smlalbb(ref IntPtr buffer, Condition cond)
        {
            *(uint*)(*buf) = (16777856 | cond);
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>smlalbt</c> instruction.</summary>
        public static void smlalbt(ref IntPtr buffer, Condition cond)
        {
            *(uint*)(*buf) = (83886720 | cond);
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>smlaltb</c> instruction.</summary>
        public static void smlaltb(ref IntPtr buffer, Condition cond)
        {
            *(uint*)(*buf) = (50332288 | cond);
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>smlaltt</c> instruction.</summary>
        public static void smlaltt(ref IntPtr buffer, Condition cond)
        {
            *(uint*)(*buf) = (117441152 | cond);
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>smlald</c> instruction.</summary>
        public static void smlald(ref IntPtr buffer, Condition cond)
        {
            *(uint*)(*buf) = (67109600 | cond);
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>smlawb</c> instruction.</summary>
        public static void smlawb(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((16778368 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>smlawt</c> instruction.</summary>
        public static void smlawt(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((50332800 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>smlsd</c> instruction.</summary>
        public static void smlsd(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((100663520 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>smlsld</c> instruction.</summary>
        public static void smlsld(ref IntPtr buffer, Condition cond)
        {
            *(uint*)(*buf) = (100664032 | cond);
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>smmla</c> instruction.</summary>
        public static void smmla(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((134220512 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>smmls</c> instruction.</summary>
        public static void smmls(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((184552160 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>smmul</c> instruction.</summary>
        public static void smmul(ref IntPtr buffer, Condition cond, Reg rd)
        {
            *(uint*)(*buf) = ((135203552 | cond) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>smuad</c> instruction.</summary>
        public static void smuad(ref IntPtr buffer, Condition cond, Reg rd)
        {
            *(uint*)(*buf) = ((68092128 | cond) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>smulbb</c> instruction.</summary>
        public static void smulbb(ref IntPtr buffer, Condition cond, Reg rd)
        {
            *(uint*)(*buf) = ((16778880 | cond) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>smulbt</c> instruction.</summary>
        public static void smulbt(ref IntPtr buffer, Condition cond, Reg rd)
        {
            *(uint*)(*buf) = ((83887744 | cond) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>smultb</c> instruction.</summary>
        public static void smultb(ref IntPtr buffer, Condition cond, Reg rd)
        {
            *(uint*)(*buf) = ((50333312 | cond) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>smultt</c> instruction.</summary>
        public static void smultt(ref IntPtr buffer, Condition cond, Reg rd)
        {
            *(uint*)(*buf) = ((117442176 | cond) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>smull</c> instruction.</summary>
        public static void smull(ref IntPtr buffer, Condition cond, bool s)
        {
            *(uint*)(*buf) = ((301991424 | cond) | (s << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>smulwb</c> instruction.</summary>
        public static void smulwb(ref IntPtr buffer, Condition cond, Reg rd)
        {
            *(uint*)(*buf) = ((83887232 | cond) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>smulwt</c> instruction.</summary>
        public static void smulwt(ref IntPtr buffer, Condition cond, Reg rd)
        {
            *(uint*)(*buf) = ((117441664 | cond) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>smusd</c> instruction.</summary>
        public static void smusd(ref IntPtr buffer, Condition cond, Reg rd)
        {
            *(uint*)(*buf) = ((101646560 | cond) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>srs</c> instruction.</summary>
        public static void srs(ref IntPtr buffer, bool write, Mode mode)
        {
            *(uint*)(*buf) = ((2632863 | (write << 8)) | (mode << 26));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>ssat</c> instruction.</summary>
        public static void ssat(ref IntPtr buffer, Condition cond, Reg rd)
        {
            *(uint*)(*buf) = ((133728 | cond) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>ssat16</c> instruction.</summary>
        public static void ssat16(ref IntPtr buffer, Condition cond, Reg rd)
        {
            *(uint*)(*buf) = ((13567328 | cond) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>ssub16</c> instruction.</summary>
        public static void ssub16(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((250611808 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>ssub8</c> instruction.</summary>
        public static void ssub8(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((267389024 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>ssubaddx</c> instruction.</summary>
        public static void ssubaddx(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((183502944 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>stc</c> instruction.</summary>
        public static void stc(ref IntPtr buffer, Condition cond, bool write, Reg rn)
        {
            *(uint*)(*buf) = (((48 | cond) | (write << 8)) | (rn << 10));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>stm1</c> instruction.</summary>
        public static void stm1(ref IntPtr buffer, Condition cond, bool write, Reg rn)
        {
            *(uint*)(*buf) = (((16 | cond) | (write << 8)) | (rn << 10));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>stm2</c> instruction.</summary>
        public static void stm2(ref IntPtr buffer, Condition cond, Reg rn)
        {
            *(uint*)(*buf) = ((144 | cond) | (rn << 10));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>str</c> instruction.</summary>
        public static void str(ref IntPtr buffer, Condition cond, bool write, bool i, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((((32 | cond) | (write << 8)) | (i << 6)) | (rn << 10)) | (rd << 14));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>strb</c> instruction.</summary>
        public static void strb(ref IntPtr buffer, Condition cond, bool write, bool i, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((((160 | cond) | (write << 8)) | (i << 6)) | (rn << 10)) | (rd << 14));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>strbt</c> instruction.</summary>
        public static void strbt(ref IntPtr buffer, Condition cond, bool i, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = ((((800 | cond) | (i << 6)) | (rn << 11)) | (rd << 15));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>strd</c> instruction.</summary>
        public static void strd(ref IntPtr buffer, Condition cond, bool write, bool i, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((((3932160 | cond) | (write << 8)) | (i << 7)) | (rn << 10)) | (rd << 14));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>strex</c> instruction.</summary>
        public static void strex(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((83362176 | cond) | (rn << 11)) | (rd << 15));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>strh</c> instruction.</summary>
        public static void strh(ref IntPtr buffer, Condition cond, bool write, bool i, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((((3407872 | cond) | (write << 8)) | (i << 7)) | (rn << 10)) | (rd << 14));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>strt</c> instruction.</summary>
        public static void strt(ref IntPtr buffer, Condition cond, bool i, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = ((((544 | cond) | (i << 6)) | (rn << 11)) | (rd << 15));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>swi</c> instruction.</summary>
        public static void swi(ref IntPtr buffer, Condition cond)
        {
            *(uint*)(*buf) = (240 | cond);
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>swp</c> instruction.</summary>
        public static void swp(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((150995072 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>swpb</c> instruction.</summary>
        public static void swpb(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((150995584 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>sxtab</c> instruction.</summary>
        public static void sxtab(ref IntPtr buffer, Condition cond, Reg rn, Reg rd, Rotation rotate)
        {
            *(uint*)(*buf) = ((((234882400 | cond) | (rn << 12)) | (rd << 16)) | (rotate << 20));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>sxtab16</c> instruction.</summary>
        public static void sxtab16(ref IntPtr buffer, Condition cond, Reg rn, Reg rd, Rotation rotate)
        {
            *(uint*)(*buf) = ((((234881376 | cond) | (rn << 12)) | (rd << 16)) | (rotate << 20));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>sxtah</c> instruction.</summary>
        public static void sxtah(ref IntPtr buffer, Condition cond, Reg rn, Reg rd, Rotation rotate)
        {
            *(uint*)(*buf) = ((((234884448 | cond) | (rn << 12)) | (rd << 16)) | (rotate << 20));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>sxtb</c> instruction.</summary>
        public static void sxtb(ref IntPtr buffer, Condition cond, Reg rd, Rotation rotate)
        {
            *(uint*)(*buf) = (((234943840 | cond) | (rd << 16)) | (rotate << 20));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>sxtb16</c> instruction.</summary>
        public static void sxtb16(ref IntPtr buffer, Condition cond, Reg rd, Rotation rotate)
        {
            *(uint*)(*buf) = (((234942816 | cond) | (rd << 16)) | (rotate << 20));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>sxth</c> instruction.</summary>
        public static void sxth(ref IntPtr buffer, Condition cond, Reg rd, Rotation rotate)
        {
            *(uint*)(*buf) = (((234945888 | cond) | (rd << 16)) | (rotate << 20));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>teq</c> instruction.</summary>
        public static void teq(ref IntPtr buffer, Condition cond, bool i, Reg rn)
        {
            *(uint*)(*buf) = (((3200 | cond) | (i << 6)) | (rn << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits a <c>tst</c> instruction.</summary>
        public static void tst(ref IntPtr buffer, Condition cond, bool i, Reg rn)
        {
            *(uint*)(*buf) = (((2176 | cond) | (i << 6)) | (rn << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an <c>uadd16</c> instruction.</summary>
        public static void uadd16(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((149949024 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an <c>uadd8</c> instruction.</summary>
        public static void uadd8(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((166726240 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an <c>uaddsubx</c> instruction.</summary>
        public static void uaddsubx(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((217057888 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an <c>uhadd16</c> instruction.</summary>
        public static void uhadd16(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((149950048 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an <c>uhadd8</c> instruction.</summary>
        public static void uhadd8(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((166727264 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an <c>uhaddsubx</c> instruction.</summary>
        public static void uhaddsubx(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((217058912 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an <c>uhsub16</c> instruction.</summary>
        public static void uhsub16(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((250613344 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an <c>uhsub8</c> instruction.</summary>
        public static void uhsub8(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((267390560 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an <c>uhsubaddx</c> instruction.</summary>
        public static void uhsubaddx(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((183504480 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an <c>umaal</c> instruction.</summary>
        public static void umaal(ref IntPtr buffer, Condition cond)
        {
            *(uint*)(*buf) = (150995456 | cond);
            *(byte*)buf += 4;
        }

        /// <summary>Emits an <c>umlal</c> instruction.</summary>
        public static void umlal(ref IntPtr buffer, Condition cond, bool s)
        {
            *(uint*)(*buf) = ((150996224 | cond) | (s << 11));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an <c>umull</c> instruction.</summary>
        public static void umull(ref IntPtr buffer, Condition cond, bool s)
        {
            *(uint*)(*buf) = ((150995200 | cond) | (s << 11));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an <c>uqadd16</c> instruction.</summary>
        public static void uqadd16(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((149948000 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an <c>uqadd8</c> instruction.</summary>
        public static void uqadd8(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((166725216 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an <c>uqaddsubx</c> instruction.</summary>
        public static void uqaddsubx(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((217056864 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an <c>uqsub16</c> instruction.</summary>
        public static void uqsub16(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((250611296 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an <c>uqsub8</c> instruction.</summary>
        public static void uqsub8(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((267388512 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an <c>uqsubaddx</c> instruction.</summary>
        public static void uqsubaddx(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((183502432 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an <c>usad8</c> instruction.</summary>
        public static void usad8(ref IntPtr buffer, Condition cond, Reg rd)
        {
            *(uint*)(*buf) = ((135201248 | cond) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an <c>usada8</c> instruction.</summary>
        public static void usada8(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((134218208 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an <c>usat</c> instruction.</summary>
        public static void usat(ref IntPtr buffer, Condition cond, Reg rd)
        {
            *(uint*)(*buf) = ((67424 | cond) | (rd << 11));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an <c>usat16</c> instruction.</summary>
        public static void usat16(ref IntPtr buffer, Condition cond, Reg rd)
        {
            *(uint*)(*buf) = ((13567840 | cond) | (rd << 12));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an <c>usub16</c> instruction.</summary>
        public static void usub16(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((250612320 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an <c>usub8</c> instruction.</summary>
        public static void usub8(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((267389536 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an <c>usubaddx</c> instruction.</summary>
        public static void usubaddx(ref IntPtr buffer, Condition cond, Reg rn, Reg rd)
        {
            *(uint*)(*buf) = (((183503456 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an <c>uxtab</c> instruction.</summary>
        public static void uxtab(ref IntPtr buffer, Condition cond, Reg rn, Reg rd, Rotation rotate)
        {
            *(uint*)(*buf) = ((((234882912 | cond) | (rn << 12)) | (rd << 16)) | (rotate << 20));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an <c>uxtab16</c> instruction.</summary>
        public static void uxtab16(ref IntPtr buffer, Condition cond, Reg rn, Reg rd, Rotation rotate)
        {
            *(uint*)(*buf) = ((((234881888 | cond) | (rn << 12)) | (rd << 16)) | (rotate << 20));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an <c>uxtah</c> instruction.</summary>
        public static void uxtah(ref IntPtr buffer, Condition cond, Reg rn, Reg rd, Rotation rotate)
        {
            *(uint*)(*buf) = ((((234884960 | cond) | (rn << 12)) | (rd << 16)) | (rotate << 20));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an <c>uxtb</c> instruction.</summary>
        public static void uxtb(ref IntPtr buffer, Condition cond, Reg rd, Rotation rotate)
        {
            *(uint*)(*buf) = (((234944352 | cond) | (rd << 16)) | (rotate << 20));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an <c>uxtb16</c> instruction.</summary>
        public static void uxtb16(ref IntPtr buffer, Condition cond, Reg rd, Rotation rotate)
        {
            *(uint*)(*buf) = (((234943328 | cond) | (rd << 16)) | (rotate << 20));
            *(byte*)buf += 4;
        }

        /// <summary>Emits an <c>uxth</c> instruction.</summary>
        public static void uxth(ref IntPtr buffer, Condition cond, Reg rd, Rotation rotate)
        {
            *(uint*)(*buf) = (((234946400 | cond) | (rd << 16)) | (rotate << 20));
            *(byte*)buf += 4;
        }


    }
}
