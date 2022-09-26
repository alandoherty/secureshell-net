using System;
using System.Buffers;
using System.Numerics;

namespace SecureShell.Transport.Utilities
{
    internal static class MpInteger
    {
        internal static int GetByteCount(BigInteger bigInteger)
        {
            // RFC4251 states that zero "mpint" is represented by a zero length array
            if (bigInteger == BigInteger.Zero)
                return 0;
            
            return bigInteger.GetByteCount();
        }

        internal static bool TryWriteBytes(BigInteger bigInteger, Span<byte> buffer, out int bytesWritten)
        {
            // RFC4251 states that zero "mpint" is represented by a zero length array
            if (bigInteger == BigInteger.Zero) {
                bytesWritten = 0;
                return true;
            }
            
            return bigInteger.TryWriteBytes(buffer, out bytesWritten, false, true);
        }
        
        internal static byte[] ToByteArray(BigInteger bigInteger)
        {
            byte[] arr = new byte[GetByteCount(bigInteger)];
            if (!TryWriteBytes(bigInteger, arr.AsSpan(), out _))
                throw new Exception("Failed to write byte array");
            return arr;
        }
    }
}