using System;
using System.Security.Cryptography;

namespace SecureShell.Security.Encryption
{
    public class SymmetricEncryptionAlgorithm : EncryptionAlgorithm
    {
        private readonly CipherMode _mode;
        private readonly SymmetricAlgorithm _alg;
        
        public override int BlockSize => _alg.BlockSize;
        
        public override bool TryEncrypt(ReadOnlySpan<byte> inBuffer, Span<byte> outBuffer, out int bytesWritten)
        {
            if (_mode == CipherMode.ECB) {
                return _alg.TryEncryptEcb(inBuffer, outBuffer, PaddingMode.None, out bytesWritten);
            } else if (_mode == CipherMode.CBC) {
                throw new NotImplementedException();
            } else if (_mode == CipherMode.CFB) {
                throw new NotImplementedException();
            } else {
                throw new NotSupportedException();
            }
        }

        public override bool TryDecrypt(ReadOnlySpan<byte> inBuffer, Span<byte> outBuffer, out int bytesWritten)
        {
            if (_mode == CipherMode.ECB) {
                return _alg.TryDecryptEcb(inBuffer, outBuffer, PaddingMode.None, out bytesWritten);
            } else if (_mode == CipherMode.CBC) {
                throw new NotImplementedException();
            } else if (_mode == CipherMode.CFB) {
                throw new NotImplementedException();
            } else {
                throw new NotSupportedException();
            }
        }

        public SymmetricEncryptionAlgorithm(SymmetricAlgorithm alg, CipherMode mode)
        {
            if (mode != CipherMode.CBC && mode != CipherMode.CFB && mode != CipherMode.ECB) {
                throw new ArgumentException("The cipher mode is not supported", nameof(mode));
            }
            
            _alg = alg;
            _mode = mode;
        }
    }
}