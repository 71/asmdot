using System;
using System.Runtime.InteropServices;

namespace Asm.Net
{
    partial class Arm
    {
        /// <summary>Emits an <c>adc</c> instruction.</summary>
        public static byte adc(Condition cond, bool i, bool s, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((((1280 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits an <c>add</c> instruction.</summary>
        public static byte add(Condition cond, bool i, bool s, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((((256 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits an <c>and</c> instruction.</summary>
        public static byte and(Condition cond, bool i, bool s, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((((0 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits an <c>eor</c> instruction.</summary>
        public static byte eor(Condition cond, bool i, bool s, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((((1024 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits an <c>orr</c> instruction.</summary>
        public static byte orr(Condition cond, bool i, bool s, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((((384 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>rsb</c> instruction.</summary>
        public static byte rsb(Condition cond, bool i, bool s, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((((1536 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>rsc</c> instruction.</summary>
        public static byte rsc(Condition cond, bool i, bool s, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((((1792 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>sbc</c> instruction.</summary>
        public static byte sbc(Condition cond, bool i, bool s, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((((768 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>sub</c> instruction.</summary>
        public static byte sub(Condition cond, bool i, bool s, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((((512 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>bkpt</c> instruction.</summary>
        public static byte bkpt(ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = 234882183;
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>b</c> instruction.</summary>
        public static byte b(Condition cond, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (80 | cond);
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>bic</c> instruction.</summary>
        public static byte bic(Condition cond, bool i, bool s, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((((896 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>blx</c> instruction.</summary>
        public static byte blx(Condition cond, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (218100864 | cond);
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>bx</c> instruction.</summary>
        public static byte bx(Condition cond, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (150992000 | cond);
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>bxj</c> instruction.</summary>
        public static byte bxj(Condition cond, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (83883136 | cond);
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>blxun</c> instruction.</summary>
        public static byte blxun(ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = 95;
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>cdp</c> instruction.</summary>
        public static byte cdp(Condition cond, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (112 | cond);
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>clz</c> instruction.</summary>
        public static byte clz(Condition cond, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = ((150009472 | cond) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>cmn</c> instruction.</summary>
        public static byte cmn(Condition cond, bool i, reg rn, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((3712 | cond) | (i ? 64 : 0)) | (rn << 12));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>cmp</c> instruction.</summary>
        public static byte cmp(Condition cond, bool i, reg rn, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((2688 | cond) | (i ? 64 : 0)) | (rn << 12));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>cpy</c> instruction.</summary>
        public static byte cpy(Condition cond, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = ((1408 | cond) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>cps</c> instruction.</summary>
        public static byte cps(Mode mode, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (16527 | (mode << 24));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>cpsie</c> instruction.</summary>
        public static byte cpsie(ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = 4239;
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>cpsid</c> instruction.</summary>
        public static byte cpsid(ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = 12431;
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>cpsie_mode</c> instruction.</summary>
        public static byte cpsie_mode(Mode mode, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (20623 | (mode << 21));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>cpsid_mode</c> instruction.</summary>
        public static byte cpsid_mode(Mode mode, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (28815 | (mode << 21));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>ldc</c> instruction.</summary>
        public static byte ldc(Condition cond, bool write, reg rn, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((560 | cond) | (write ? 256 : 0)) | (rn << 10));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>ldm1</c> instruction.</summary>
        public static byte ldm1(Condition cond, bool write, reg rn, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((528 | cond) | (write ? 256 : 0)) | (rn << 10));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>ldm2</c> instruction.</summary>
        public static byte ldm2(Condition cond, reg rn, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = ((656 | cond) | (rn << 10));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>ldm3</c> instruction.</summary>
        public static byte ldm3(Condition cond, bool write, reg rn, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((17040 | cond) | (write ? 256 : 0)) | (rn << 10));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>ldr</c> instruction.</summary>
        public static byte ldr(Condition cond, bool write, bool i, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((((544 | cond) | (write ? 256 : 0)) | (i ? 64 : 0)) | (rn << 10)) | (rd << 14));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>ldrb</c> instruction.</summary>
        public static byte ldrb(Condition cond, bool write, bool i, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((((672 | cond) | (write ? 256 : 0)) | (i ? 64 : 0)) | (rn << 10)) | (rd << 14));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>ldrbt</c> instruction.</summary>
        public static byte ldrbt(Condition cond, bool i, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = ((((1824 | cond) | (i ? 64 : 0)) | (rn << 11)) | (rd << 15));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>ldrd</c> instruction.</summary>
        public static byte ldrd(Condition cond, bool write, bool i, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((((2883584 | cond) | (write ? 256 : 0)) | (i ? 128 : 0)) | (rn << 10)) | (rd << 14));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>ldrex</c> instruction.</summary>
        public static byte ldrex(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((4193257856 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>ldrh</c> instruction.</summary>
        public static byte ldrh(Condition cond, bool write, bool i, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((((3408384 | cond) | (write ? 256 : 0)) | (i ? 128 : 0)) | (rn << 10)) | (rd << 14));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>ldrsb</c> instruction.</summary>
        public static byte ldrsb(Condition cond, bool write, bool i, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((((2884096 | cond) | (write ? 256 : 0)) | (i ? 128 : 0)) | (rn << 10)) | (rd << 14));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>ldrsh</c> instruction.</summary>
        public static byte ldrsh(Condition cond, bool write, bool i, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((((3932672 | cond) | (write ? 256 : 0)) | (i ? 128 : 0)) | (rn << 10)) | (rd << 14));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>ldrt</c> instruction.</summary>
        public static byte ldrt(Condition cond, bool i, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = ((((1568 | cond) | (i ? 64 : 0)) | (rn << 11)) | (rd << 15));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>mcr</c> instruction.</summary>
        public static byte mcr(Condition cond, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = ((131184 | cond) | (rd << 13));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>mcrr</c> instruction.</summary>
        public static byte mcrr(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((560 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>mla</c> instruction.</summary>
        public static byte mla(Condition cond, bool s, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = ((((150995968 | cond) | (s ? 2048 : 0)) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>mov</c> instruction.</summary>
        public static byte mov(Condition cond, bool i, bool s, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = ((((1408 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>mrc</c> instruction.</summary>
        public static byte mrc(Condition cond, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = ((131440 | cond) | (rd << 13));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>mrrc</c> instruction.</summary>
        public static byte mrrc(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((2608 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>mrs</c> instruction.</summary>
        public static byte mrs(Condition cond, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = ((61568 | cond) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>mul</c> instruction.</summary>
        public static byte mul(Condition cond, bool s, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((150994944 | cond) | (s ? 2048 : 0)) | (rd << 12));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>mvn</c> instruction.</summary>
        public static byte mvn(Condition cond, bool i, bool s, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = ((((1920 | cond) | (i ? 64 : 0)) | (s ? 2048 : 0)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>msr_imm</c> instruction.</summary>
        public static byte msr_imm(Condition cond, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (62656 | cond);
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>msr_reg</c> instruction.</summary>
        public static byte msr_reg(Condition cond, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (62592 | cond);
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>pkhbt</c> instruction.</summary>
        public static byte pkhbt(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((134218080 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>pkhtb</c> instruction.</summary>
        public static byte pkhtb(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((167772512 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>pld</c> instruction.</summary>
        public static byte pld(bool i, reg rn, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = ((492975 | (i ? 64 : 0)) | (rn << 11));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>qadd</c> instruction.</summary>
        public static byte qadd(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((167772288 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>qadd16</c> instruction.</summary>
        public static byte qadd16(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((149947488 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>qadd8</c> instruction.</summary>
        public static byte qadd8(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((166724704 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>qaddsubx</c> instruction.</summary>
        public static byte qaddsubx(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((217056352 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>qdadd</c> instruction.</summary>
        public static byte qdadd(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((167772800 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>qdsub</c> instruction.</summary>
        public static byte qdsub(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((167773824 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>qsub</c> instruction.</summary>
        public static byte qsub(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((167773312 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>qsub16</c> instruction.</summary>
        public static byte qsub16(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((250610784 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>qsub8</c> instruction.</summary>
        public static byte qsub8(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((267388000 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>qsubaddx</c> instruction.</summary>
        public static byte qsubaddx(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((183501920 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>rev</c> instruction.</summary>
        public static byte rev(Condition cond, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = ((217120096 | cond) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>rev16</c> instruction.</summary>
        public static byte rev16(Condition cond, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = ((233897312 | cond) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>revsh</c> instruction.</summary>
        public static byte revsh(Condition cond, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = ((233897824 | cond) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>rfe</c> instruction.</summary>
        public static byte rfe(bool write, reg rn, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = ((1311263 | (write ? 256 : 0)) | (rn << 10));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>sadd16</c> instruction.</summary>
        public static byte sadd16(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((149948512 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>sadd8</c> instruction.</summary>
        public static byte sadd8(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((166725728 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>saddsubx</c> instruction.</summary>
        public static byte saddsubx(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((217057376 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>sel</c> instruction.</summary>
        public static byte sel(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((233832800 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>setendbe</c> instruction.</summary>
        public static byte setendbe(ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = 4227215;
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>setendle</c> instruction.</summary>
        public static byte setendle(ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = 32911;
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>shadd16</c> instruction.</summary>
        public static byte shadd16(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((149949536 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>shadd8</c> instruction.</summary>
        public static byte shadd8(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((166726752 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>shaddsubx</c> instruction.</summary>
        public static byte shaddsubx(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((217058400 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>shsub16</c> instruction.</summary>
        public static byte shsub16(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((250612832 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>shsub8</c> instruction.</summary>
        public static byte shsub8(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((267390048 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>shsubaddx</c> instruction.</summary>
        public static byte shsubaddx(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((183503968 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>smlabb</c> instruction.</summary>
        public static byte smlabb(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((16777344 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>smlabt</c> instruction.</summary>
        public static byte smlabt(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((83886208 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>smlatb</c> instruction.</summary>
        public static byte smlatb(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((50331776 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>smlatt</c> instruction.</summary>
        public static byte smlatt(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((117440640 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>smlad</c> instruction.</summary>
        public static byte smlad(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((67109088 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>smlal</c> instruction.</summary>
        public static byte smlal(Condition cond, bool s, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = ((150996736 | cond) | (s ? 2048 : 0));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>smlalbb</c> instruction.</summary>
        public static byte smlalbb(Condition cond, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (16777856 | cond);
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>smlalbt</c> instruction.</summary>
        public static byte smlalbt(Condition cond, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (83886720 | cond);
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>smlaltb</c> instruction.</summary>
        public static byte smlaltb(Condition cond, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (50332288 | cond);
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>smlaltt</c> instruction.</summary>
        public static byte smlaltt(Condition cond, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (117441152 | cond);
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>smlald</c> instruction.</summary>
        public static byte smlald(Condition cond, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (67109600 | cond);
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>smlawb</c> instruction.</summary>
        public static byte smlawb(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((16778368 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>smlawt</c> instruction.</summary>
        public static byte smlawt(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((50332800 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>smlsd</c> instruction.</summary>
        public static byte smlsd(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((100663520 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>smlsld</c> instruction.</summary>
        public static byte smlsld(Condition cond, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (100664032 | cond);
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>smmla</c> instruction.</summary>
        public static byte smmla(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((134220512 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>smmls</c> instruction.</summary>
        public static byte smmls(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((184552160 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>smmul</c> instruction.</summary>
        public static byte smmul(Condition cond, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = ((135203552 | cond) | (rd << 12));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>smuad</c> instruction.</summary>
        public static byte smuad(Condition cond, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = ((68092128 | cond) | (rd << 12));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>smulbb</c> instruction.</summary>
        public static byte smulbb(Condition cond, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = ((16778880 | cond) | (rd << 12));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>smulbt</c> instruction.</summary>
        public static byte smulbt(Condition cond, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = ((83887744 | cond) | (rd << 12));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>smultb</c> instruction.</summary>
        public static byte smultb(Condition cond, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = ((50333312 | cond) | (rd << 12));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>smultt</c> instruction.</summary>
        public static byte smultt(Condition cond, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = ((117442176 | cond) | (rd << 12));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>smull</c> instruction.</summary>
        public static byte smull(Condition cond, bool s, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = ((301991424 | cond) | (s ? 4096 : 0));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>smulwb</c> instruction.</summary>
        public static byte smulwb(Condition cond, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = ((83887232 | cond) | (rd << 12));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>smulwt</c> instruction.</summary>
        public static byte smulwt(Condition cond, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = ((117441664 | cond) | (rd << 12));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>smusd</c> instruction.</summary>
        public static byte smusd(Condition cond, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = ((101646560 | cond) | (rd << 12));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>srs</c> instruction.</summary>
        public static byte srs(bool write, Mode mode, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = ((2632863 | (write ? 256 : 0)) | (mode << 26));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>ssat</c> instruction.</summary>
        public static byte ssat(Condition cond, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = ((133728 | cond) | (rd << 12));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>ssat16</c> instruction.</summary>
        public static byte ssat16(Condition cond, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = ((13567328 | cond) | (rd << 12));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>ssub16</c> instruction.</summary>
        public static byte ssub16(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((250611808 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>ssub8</c> instruction.</summary>
        public static byte ssub8(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((267389024 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>ssubaddx</c> instruction.</summary>
        public static byte ssubaddx(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((183502944 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>stc</c> instruction.</summary>
        public static byte stc(Condition cond, bool write, reg rn, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((48 | cond) | (write ? 256 : 0)) | (rn << 10));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>stm1</c> instruction.</summary>
        public static byte stm1(Condition cond, bool write, reg rn, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((16 | cond) | (write ? 256 : 0)) | (rn << 10));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>stm2</c> instruction.</summary>
        public static byte stm2(Condition cond, reg rn, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = ((144 | cond) | (rn << 10));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>str</c> instruction.</summary>
        public static byte str(Condition cond, bool write, bool i, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((((32 | cond) | (write ? 256 : 0)) | (i ? 64 : 0)) | (rn << 10)) | (rd << 14));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>strb</c> instruction.</summary>
        public static byte strb(Condition cond, bool write, bool i, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((((160 | cond) | (write ? 256 : 0)) | (i ? 64 : 0)) | (rn << 10)) | (rd << 14));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>strbt</c> instruction.</summary>
        public static byte strbt(Condition cond, bool i, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = ((((800 | cond) | (i ? 64 : 0)) | (rn << 11)) | (rd << 15));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>strd</c> instruction.</summary>
        public static byte strd(Condition cond, bool write, bool i, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((((3932160 | cond) | (write ? 256 : 0)) | (i ? 128 : 0)) | (rn << 10)) | (rd << 14));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>strex</c> instruction.</summary>
        public static byte strex(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((83362176 | cond) | (rn << 11)) | (rd << 15));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>strh</c> instruction.</summary>
        public static byte strh(Condition cond, bool write, bool i, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((((3407872 | cond) | (write ? 256 : 0)) | (i ? 128 : 0)) | (rn << 10)) | (rd << 14));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>strt</c> instruction.</summary>
        public static byte strt(Condition cond, bool i, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = ((((544 | cond) | (i ? 64 : 0)) | (rn << 11)) | (rd << 15));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>swi</c> instruction.</summary>
        public static byte swi(Condition cond, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (240 | cond);
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>swp</c> instruction.</summary>
        public static byte swp(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((150995072 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>swpb</c> instruction.</summary>
        public static byte swpb(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((150995584 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>sxtab</c> instruction.</summary>
        public static byte sxtab(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((58721632 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>sxtab16</c> instruction.</summary>
        public static byte sxtab16(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((58720608 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>sxtah</c> instruction.</summary>
        public static byte sxtah(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((58723680 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>sxtb</c> instruction.</summary>
        public static byte sxtb(Condition cond, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = ((58783072 | cond) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>sxtb16</c> instruction.</summary>
        public static byte sxtb16(Condition cond, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = ((58782048 | cond) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>sxth</c> instruction.</summary>
        public static byte sxth(Condition cond, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = ((58785120 | cond) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>teq</c> instruction.</summary>
        public static byte teq(Condition cond, bool i, reg rn, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((3200 | cond) | (i ? 64 : 0)) | (rn << 12));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits a <c>tst</c> instruction.</summary>
        public static byte tst(Condition cond, bool i, reg rn, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((2176 | cond) | (i ? 64 : 0)) | (rn << 12));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits an <c>uadd16</c> instruction.</summary>
        public static byte uadd16(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((149949024 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits an <c>uadd8</c> instruction.</summary>
        public static byte uadd8(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((166726240 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits an <c>uaddsubx</c> instruction.</summary>
        public static byte uaddsubx(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((217057888 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits an <c>uhadd16</c> instruction.</summary>
        public static byte uhadd16(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((149950048 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits an <c>uhadd8</c> instruction.</summary>
        public static byte uhadd8(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((166727264 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits an <c>uhaddsubx</c> instruction.</summary>
        public static byte uhaddsubx(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((217058912 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits an <c>uhsub16</c> instruction.</summary>
        public static byte uhsub16(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((250613344 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits an <c>uhsub8</c> instruction.</summary>
        public static byte uhsub8(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((267390560 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits an <c>uhsubaddx</c> instruction.</summary>
        public static byte uhsubaddx(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((183504480 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits an <c>umaal</c> instruction.</summary>
        public static byte umaal(Condition cond, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (150995456 | cond);
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits an <c>umlal</c> instruction.</summary>
        public static byte umlal(Condition cond, bool s, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = ((150996224 | cond) | (s ? 2048 : 0));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits an <c>umull</c> instruction.</summary>
        public static byte umull(Condition cond, bool s, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = ((150995200 | cond) | (s ? 2048 : 0));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits an <c>uqadd16</c> instruction.</summary>
        public static byte uqadd16(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((149948000 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits an <c>uqadd8</c> instruction.</summary>
        public static byte uqadd8(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((166725216 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits an <c>uqaddsubx</c> instruction.</summary>
        public static byte uqaddsubx(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((217056864 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits an <c>uqsub16</c> instruction.</summary>
        public static byte uqsub16(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((250611296 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits an <c>uqsub8</c> instruction.</summary>
        public static byte uqsub8(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((267388512 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits an <c>uqsubaddx</c> instruction.</summary>
        public static byte uqsubaddx(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((183502432 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits an <c>usad8</c> instruction.</summary>
        public static byte usad8(Condition cond, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = ((135201248 | cond) | (rd << 12));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits an <c>usada8</c> instruction.</summary>
        public static byte usada8(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((134218208 | cond) | (rn << 16)) | (rd << 12));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits an <c>usat</c> instruction.</summary>
        public static byte usat(Condition cond, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = ((67424 | cond) | (rd << 11));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits an <c>usat16</c> instruction.</summary>
        public static byte usat16(Condition cond, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = ((13567840 | cond) | (rd << 12));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits an <c>usub16</c> instruction.</summary>
        public static byte usub16(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((250612320 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits an <c>usub8</c> instruction.</summary>
        public static byte usub8(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((267389536 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits an <c>usubaddx</c> instruction.</summary>
        public static byte usubaddx(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((183503456 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits an <c>uxtab</c> instruction.</summary>
        public static byte uxtab(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((58722144 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits an <c>uxtab16</c> instruction.</summary>
        public static byte uxtab16(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((58721120 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits an <c>uxtah</c> instruction.</summary>
        public static byte uxtah(Condition cond, reg rn, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = (((58724192 | cond) | (rn << 12)) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits an <c>uxtb</c> instruction.</summary>
        public static byte uxtb(Condition cond, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = ((58783584 | cond) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits an <c>uxtb16</c> instruction.</summary>
        public static byte uxtb16(Condition cond, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = ((58782560 | cond) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }

        /// <summary>Emits an <c>uxth</c> instruction.</summary>
        public static byte uxth(Condition cond, reg rd, ref IntPtr buffer)
        {
            *(int*)(*buf + 0) = ((58785632 | cond) | (rd << 16));
            *(byte*)buf += 4;
            return 4;
        }


    }
}
