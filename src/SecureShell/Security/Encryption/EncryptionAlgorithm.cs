using System;

namespace SecureShell.Security.Encryption
{
    
    public abstract class EncryptionAlgorithm
    {
        /// <summary>
        /// The none algorithm.
        /// </summary>
        public static EncryptionAlgorithm None = new NoneEncryptionAlgorithm();
        
        public abstract int BlockSize { get; }

        public abstract bool TryEncrypt(ReadOnlySpan<byte> inBuffer, Span<byte> outBuffer, out int bytesWritten);
        public abstract bool TryDecrypt(ReadOnlySpan<byte> inBuffer, Span<byte> outBuffer, out int bytesWritten);
    }
}