namespace AsmSq
{
    public enum Condition : byte
    {
        /// <summary>
        /// Equal.
        /// </summary>
        EQ = 0b0000,
        /// <summary>
        /// Not equal.
        /// </summary>
        NE = 0b0001,
        /// <summary>
        /// Carry set.
        /// </summary>
        CS = 0b0010,
        /// <summary>
        /// Unsigned higher or same.
        /// </summary>
        HS = 0b0010,
        /// <summary>
        /// Carry clear.
        /// </summary>
        CC = 0b0011,
        /// <summary>
        /// Unsigned lower.
        /// </summary>
        LO = 0b0011,
        /// <summary>
        /// Minus / negative.
        /// </summary>
        MI = 0b0100,
        /// <summary>
        /// Plus / positive or zero.
        /// </summary>
        PL = 0b0101,
        /// <summary>
        /// Overflow.
        /// </summary>
        VS = 0b0110,
        /// <summary>
        /// No overflow.
        /// </summary>
        VC = 0b0111,
        /// <summary>
        /// Unsigned higher.
        /// </summary>
        HI = 0b1000,
        /// <summary>
        /// Unsigned lower or same.
        /// </summary>
        LS = 0b1001,
        /// <summary>
        /// Signed greater than or equal.
        /// </summary>
        GE = 0b1010,
        /// <summary>
        /// Signed less than.
        /// </summary>
        LT = 0b1011,
        /// <summary>
        /// Signed greater than.
        /// </summary>
        GT = 0b1100,
        /// <summary>
        /// Signed less than or equal.
        /// </summary>
        LE = 0b1101,
        /// <summary>
        /// Always (unconditional).
        /// </summary>
        AL = 0b1110,
        /// <summary>
        /// Unpredictable (ARMv4 and lower) or unconditional (ARMv5 and higher).
        /// </summary>
        UN = 0b1111
    }
}
