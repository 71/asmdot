using System;

namespace Asm.Net
{
    #region Register classes
    /// <summary>
    ///   Represents a 8-bits-wide register.
    /// </summary>
    public struct Register8
    {
        /// <summary>
        ///   Underlying value of the register.
        /// </summary>
        public readonly byte Value;

        /// <summary>
        ///   Creates an 8-bits-wide register, given its value.
        /// </summary>
        public Register8(byte value) => Value = value;

        /// <summary>
        ///   Converts a <see cref="byte"/> into a <see cref="Register8"/>.
        /// </summary>
        public static implicit operator Register8(byte r) => new Register8(r);
    
        /// <summary>
        ///   Converts a <see cref="Register8"/> into a <see cref="byte"/>.
        /// </summary>
        public static implicit operator byte(Register8 r) => r.Value;
    }

    /// <summary>
    ///   Represents a 16-bits-wide register.
    /// </summary>
    public struct Register16
    {
        /// <summary>
        ///   Underlying value of the register.
        /// </summary>
        public readonly byte Value;

        /// <summary>
        ///   Creates an 16-bits-wide register, given its value.
        /// </summary>
        public Register16(byte value) => Value = value;

        /// <summary>
        ///   Converts a <see cref="byte"/> into a <see cref="Register16"/>.
        /// </summary>
        public static implicit operator Register16(byte r) => new Register16(r);
    
        /// <summary>
        ///   Converts a <see cref="Register16"/> into a <see cref="byte"/>.
        /// </summary>
        public static implicit operator byte(Register16 r) => r.Value;
    }

    /// <summary>
    ///   Represents a 32-bits-wide register.
    /// </summary>
    public struct Register32
    {
        /// <summary>
        ///   Underlying value of the register.
        /// </summary>
        public readonly byte Value;

        /// <summary>
        ///   Creates an 32-bits-wide register, given its value.
        /// </summary>
        public Register32(byte value) => Value = value;

        /// <summary>
        ///   Converts a <see cref="byte"/> into a <see cref="Register32"/>.
        /// </summary>
        public static implicit operator Register32(byte r) => new Register32(r);
    
        /// <summary>
        ///   Converts a <see cref="Register32"/> into a <see cref="byte"/>.
        /// </summary>
        public static implicit operator byte(Register32 r) => r.Value;
    }

    /// <summary>
    ///   Represents a 64-bits-wide register.
    /// </summary>
    public struct Register64
    {
        /// <summary>
        ///   Underlying value of the register.
        /// </summary>
        public readonly byte Value;

        /// <summary>
        ///   Creates an 64-bits-wide register, given its value.
        /// </summary>
        public Register64(byte value) => Value = value;

        /// <summary>
        ///   Converts a <see cref="byte"/> into a <see cref="Register64"/>.
        /// </summary>
        public static implicit operator Register64(byte r) => new Register64(r);
    
        /// <summary>
        ///   Converts a <see cref="Register64"/> into a <see cref="byte"/>.
        /// </summary>
        public static implicit operator byte(Register64 r) => r.Value;
    }

    /// <summary>
    ///   Represents a 128-bits-wide register.
    /// </summary>
    public struct Register128
    {
        /// <summary>
        ///   Underlying value of the register.
        /// </summary>
        public readonly byte Value;

        /// <summary>
        ///   Creates an 128-bits-wide register, given its value.
        /// </summary>
        public Register128(byte value) => Value = value;

        /// <summary>
        ///   Converts a <see cref="byte"/> into a <see cref="Register128"/>.
        /// </summary>
        public static implicit operator Register128(byte r) => new Register128(r);
    
        /// <summary>
        ///   Converts a <see cref="Register128"/> into a <see cref="byte"/>.
        /// </summary>
        public static implicit operator byte(Register128 r) => r.Value;
    }
    #endregion

    /// <summary>
    ///   Defines methods for emitting x86 instructions.
    /// </summary>
    public static partial class X86
    {
    }
}
