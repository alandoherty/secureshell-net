using System;

namespace SecureShell.Security.Encryption
{
    public class NoneEncryptionAlgorithm : EncryptionAlgorithm
    {
        public override int BlockSize => 0;
        
        public override bool TryEncrypt(ReadOnlySpan<byte> inBuffer, Span<byte> outBuffer, out int bytesWritten)
        {
            bytesWritten = default;
            return true;
        }

        public override bool TryDecrypt(ReadOnlySpan<byte> inBuffer, Span<byte> outBuffer, out int bytesWritten)
        {
            bytesWritten = default;
            return true;
        }

        public NoneEncryptionAlgorithm()
        {
        }
    }
}