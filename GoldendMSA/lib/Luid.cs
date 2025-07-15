using System;
using System.Runtime.InteropServices;

namespace GoldendMSA
{
    [StructLayout(LayoutKind.Sequential)]
    public struct LUID
    {
        public UInt32 LowPart;
        public Int32 HighPart;

        public static implicit operator ulong(LUID luid)
        {
            // enable casting to a ulong
            UInt64 Value = ((UInt64)luid.HighPart << 32);
            return Value + luid.LowPart;
        }
    }
}
