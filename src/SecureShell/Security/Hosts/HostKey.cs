using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace SecureShell.Security.Hosts
{
    /// <summary>
    /// Represents the base class for a host key.
    /// </summary>
    public abstract class HostKey
    {
        /// <summary>
        /// Gets the name of the host key algorithm.
        /// </summary>
        public abstract string Name { get; }

        /// <summary>
        /// Implement this to get the host key payload byte count.
        /// </summary>
        /// <returns>The byte count.</returns>
        protected abstract int GetPayloadByteCount();

        /// <summary>
        /// Implement this to write the host key payload.
        /// </summary>
        /// <param name="buffer">The buffer.</param>
        /// <param name="bytesWritten">The bytes written.</param>
        /// <returns>If the data was encoded fully.</returns>
        protected abstract bool TryWritePayloadBytes(Span<byte> buffer, out int bytesWritten);

        /// <summary>
        /// Gets the byte count of the complete key.
        /// </summary>
        /// <returns>The byte count.</returns>
        public virtual int GetByteCount() => 4
            + Encoding.ASCII.GetByteCount(Name)
            + GetPayloadByteCount();

        /// <summary>
        /// Implement this to get the signature payload byte count.
        /// </summary>
        /// <param name="bytes">The input bytes.</param>
        /// <param name="hash">The hash algorithm.</param>
        /// <returns>The byte count.</returns>
        protected abstract int GetSignaturePayloadByteCount(Span<byte> bytes, HashAlgorithmName hash);

        /// <summary>
        /// Gets the byte count of a complete signature.
        /// </summary>
        /// <param name="bytes">The input bytes.</param>
        /// <param name="hash">The hash algorithm.</param>
        /// <returns>The signature.</returns>
        public virtual int GetSignatureByteCount(Span<byte> bytes, HashAlgorithmName hash) => 4
            + Encoding.ASCII.GetByteCount(Name)
            + GetSignaturePayloadByteCount(bytes, hash);

        /// <summary>
        /// Try and write the complete key to the buffer, this includes the algorithm name prefix.
        /// </summary>
        /// <param name="buffer">The buffer.</param>
        /// <param name="bytesWritten">The bytes count.</param>
        /// <returns>If the data was encoded fully.</returns>
        public virtual bool TryWriteBytes(Span<byte> buffer, out int bytesWritten)
        {
            if (buffer.Length < GetByteCount()) {
                bytesWritten = 0;
                return false;
            }

            int offset = 0;
            int nameByteCount = Encoding.ASCII.GetByteCount(Name);

            if (!BitConverter.TryWriteBytes(buffer.Slice(offset, 4), nameByteCount)) {
                bytesWritten = offset;
                return false;
            }

            buffer.Slice(offset, 4).Reverse();
            offset += 4;

            if (Encoding.ASCII.GetBytes(Name.AsSpan(), buffer.Slice(offset, nameByteCount)) != nameByteCount) {
                bytesWritten = offset;
                return false;
            }

            offset += nameByteCount;

            if (!TryWritePayloadBytes(buffer.Slice(offset), out int payloadBytesWritten)) {
                bytesWritten = offset + payloadBytesWritten;
                return false;
            }

            bytesWritten = offset + payloadBytesWritten;
            return true;
        }

        /// <summary>
        /// Implement this to sign payloads.
        /// </summary>
        /// <param name="bytes">The bytes to be signed.</param>
        /// <param name="hash">The hash algorithm to use.</param>
        /// <param name="buffer">The output buffer.</param>
        /// <param name="bytesWritten">The bytes written.</param>
        /// <returns>If the signature had enough bytes to be written.</returns>
        protected abstract bool TrySignPayload(Span<byte> bytes, HashAlgorithmName hash, Span<byte> buffer, out int bytesWritten);

        /// <summary>
        /// Try and sign the provided bytes with the specified hash into the provided buffer.
        /// </summary>
        /// <param name="bytes">The bytes to be signed.</param>
        /// <param name="hash">The hash algorithm to use.</param>
        /// <param name="buffer">The output buffer.</param>
        /// <param name="bytesWritten">The bytes written.</param>
        /// <returns>If the signature had enough bytes to be written.</returns>
        public virtual bool TrySign(Span<byte> bytes, HashAlgorithmName hash, Span<byte> buffer, out int bytesWritten)
        {
            if (buffer.Length < GetSignatureByteCount(bytes, hash)) {
                bytesWritten = 0;
                return false;
            }

            int offset = 0;
            int nameByteCount = Encoding.ASCII.GetByteCount(Name);

            if (!BitConverter.TryWriteBytes(buffer.Slice(offset, 4), nameByteCount)) {
                bytesWritten = offset;
                return false;
            }

            buffer.Slice(offset, 4).Reverse();
            offset += 4;

            if (Encoding.ASCII.GetBytes(Name.AsSpan(), buffer.Slice(offset, nameByteCount)) != nameByteCount) {
                bytesWritten = offset;
                return false;
            }

            offset += nameByteCount;

            if (!TrySignPayload(bytes, hash, buffer.Slice(offset), out int payloadBytesWritten)) {
                bytesWritten = offset + payloadBytesWritten;
                return false;
            }

            bytesWritten = offset + payloadBytesWritten;
            return true;
        }

        /// <summary>
        /// Sign the provided bytes with the specified hash into the provided buffer.
        /// </summary>
        /// <param name="bytes">The bytes to be signed.</param>
        /// <param name="hash">The hash algorithm to use.</param>
        public byte[] Sign(Span<byte> bytes, HashAlgorithmName hash)
        {
            byte[] arr = new byte[GetSignatureByteCount(bytes, hash)];

            if (!TrySign(bytes, hash, arr.AsSpan(), out _))
                throw new Exception("Unexpected error writing host signature bytes");

            return arr;
        }

        /// <summary>
        /// Gets the host key as a byte array, this includes the algorithm name prefix.
        /// </summary>
        /// <returns>The byte array.</returns>
        public byte[] ToByteArray()
        {
            byte[] arr = new byte[GetByteCount()];

            if (!TryWriteBytes(arr.AsSpan(), out _))
                throw new Exception("Unexpected error writing host algorithm bytes");

            return arr;
        }
    }
}
