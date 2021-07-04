using System;
using System.Collections.Generic;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace SecureShell.Security.Hosts
{
    public sealed class RsaHostKey : HostKey
    {
        private RSAParameters? _rsaParams;
        private RSA _rsa;

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

        private void EnsureParameters()
        {
            if (_rsaParams == null) {
                _rsaParams = _rsa.ExportParameters(false);
            }
        }

        /// <inheritdoc/>
        protected override bool TryWritePayloadBytes(Span<byte> buffer, out int bytesWritten)
        {
            if (buffer.Length < GetPayloadByteCount()) {
                bytesWritten = 0;
                return false;
            }

            EnsureParameters();

            int offset = 0;
            BitConverter.TryWriteBytes(buffer.Slice(offset, 4), _rsaParams.Value.Exponent.Length);
            buffer.Slice(offset, 4).Reverse();
            offset += 4;

            _rsaParams.Value.Exponent.AsSpan().CopyTo(buffer.Slice(offset, _rsaParams.Value.Exponent.Length));
            offset += _rsaParams.Value.Exponent.Length;

            BitConverter.TryWriteBytes(buffer.Slice(offset, 4), _rsaParams.Value.Modulus.Length);
            buffer.Slice(offset, 4).Reverse();
            offset += 4;

            _rsaParams.Value.Modulus.AsSpan().CopyTo(buffer.Slice(offset, _rsaParams.Value.Modulus.Length));
            offset += _rsaParams.Value.Modulus.Length;

            bytesWritten = offset;
            return true;
        }

        /// <inheritdoc/>
        protected override int GetPayloadByteCount()
        {
            EnsureParameters();

            return 8 + _rsaParams.Value.Exponent.Length + _rsaParams.Value.Modulus.Length;
        }

        /// <inheritdoc/>
        protected override int GetSignaturePayloadByteCount(Span<byte> bytes, HashAlgorithmName hash)
        {
            return (_rsa.KeySize / 8) + 4;
        }

        /// <inheritdoc/>
        protected override bool TrySignPayload(Span<byte> bytes, HashAlgorithmName hash, Span<byte> buffer, out int bytesWritten)
        {
            if (buffer.Length < GetSignaturePayloadByteCount(bytes, hash)) {
                bytesWritten = 0;
                return false;
            }

            BitConverter.TryWriteBytes(buffer.Slice(0, 4), _rsa.KeySize / 8);
            buffer.Slice(0, 4).Reverse();

            if (!_rsa.TrySignData(bytes, buffer.Slice(4, _rsa.KeySize / 8), hash, RSASignaturePadding.Pkcs1, out int signBytesWritten)) {
                bytesWritten = 4;
                return false;
            }

            buffer.Slice(4, _rsa.KeySize / 8).Reverse();

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
        }
    }
}
