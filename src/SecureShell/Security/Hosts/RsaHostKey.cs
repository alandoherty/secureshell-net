using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace SecureShell.Security.Hosts
{
    public sealed class RsaHostKey : HostKey
    {
        private RSA _rsa;
        private BigInteger _exponent;
        private BigInteger _modulus;

        /// <summary>
        /// Gets the RSA object associated with this host algorithm.
        /// </summary>
        public RSA RSA => _rsa;

        /// <inheritdoc/>
        public override string Name => "ssh-rsa";

        /// <summary>
        /// Gets the string representation of the RSA host key in Base64.
        /// </summary>
        /// <returns>The host key string representation.</returns>
        public override string ToString()
        {
            int charCount = ((4 * GetByteCount() / 3) + 3) & ~3;

            return string.Create(Name.Length + 1 + charCount, this, (s, k) => {
                Name.AsSpan()
                    .CopyTo(s);

                s[Name.Length] = ' ';

                int byteCount = k.GetByteCount();
                Span<byte> bytes = stackalloc byte[byteCount];

                if (!k.TryWriteBytes(bytes, out _)) {
                    throw new Exception("Unexpected error occured writing RSA key to buffer");
                }

                if (!Convert.TryToBase64Chars(bytes, s.Slice(Name.Length + 1), out _, Base64FormattingOptions.None)) {
                    throw new Exception("Unexpected error occured writing Base64 to buffer");
                }
            });
        }

        /// <inheritdoc/>
        protected override bool TryWritePayloadBytes(Span<byte> buffer, out int bytesWritten)
        {
            if (buffer.Length < GetPayloadByteCount()) {
                bytesWritten = 0;
                return false;
            }

            int offset = 0;

            // exponent
            BinaryPrimitives.TryWriteInt32BigEndian(buffer.Slice(offset, 4), _exponent.GetByteCount());
            offset += 4;

            _exponent.TryWriteBytes(buffer.Slice(offset, _exponent.GetByteCount()), out int bnumBytesWritten, false, true);
            offset += bnumBytesWritten;

            // modulus
            BinaryPrimitives.TryWriteInt32BigEndian(buffer.Slice(offset, 4), _modulus.GetByteCount() + (_modulus.Sign == -1 ? 1 : 0));
            offset += 4;

            // for negative modulus we prepend a zero byte, resulting in MSB being zero flipping sign
            if (_modulus.Sign == -1) {
                buffer[offset++] = 0;
            }

            _modulus.TryWriteBytes(buffer.Slice(offset, _modulus.GetByteCount()), out bnumBytesWritten, false, true);
            offset += bnumBytesWritten;

            bytesWritten = offset;
            return true;
        }

        /// <inheritdoc/>
        protected override int GetPayloadByteCount()
        {
            return 8 
                + _exponent.GetByteCount()
                + (_modulus.Sign == -1 ? 1 : 0)
                + _modulus.GetByteCount();
        }

        /// <inheritdoc/>
        protected override int GetSignaturePayloadByteCount(ReadOnlySpan<byte> bytes, HashAlgorithmName hash)
        {
            return (_rsa.KeySize / 8) + 4;
        }

        /// <inheritdoc/>
        protected override bool TrySignPayload(ReadOnlySpan<byte> bytes, HashAlgorithmName hash, Span<byte> buffer, out int bytesWritten)
        {
            if (buffer.Length < GetSignaturePayloadByteCount(bytes, hash)) {
                bytesWritten = 0;
                return false;
            }

            BinaryPrimitives.TryWriteInt32BigEndian(buffer.Slice(0, 4), _rsa.KeySize / 8);
            if (!_rsa.TrySignData(bytes, buffer.Slice(4, _rsa.KeySize / 8), hash, RSASignaturePadding.Pkcs1, out int signBytesWritten)) {
                bytesWritten = 4;
                return false;
            }

            bytesWritten = 4 + signBytesWritten;
            return true;
        }

        /// <summary>
        /// Creates a new RSA host key with the provided <see cref="System.Security.Cryptography.RSA"/> object.
        /// </summary>
        /// <param name="rsa">The RSA object.</param>
        public RsaHostKey(RSA rsa)
        {
            _rsa = rsa;

            var parameters = _rsa.ExportParameters(false);
            _exponent = new BigInteger(parameters.Exponent);
            _modulus = new BigInteger(parameters.Modulus);
        }
    }
}
