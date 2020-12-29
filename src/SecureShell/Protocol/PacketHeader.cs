using System;
using System.Buffers;
using System.Collections.Generic;
using System.Text;

namespace SecureShell.Protocol
{
    /// <summary>
    /// Represents a packet header structure.
    /// </summary>
    public struct PacketHeader
    {
        /// <summary>
        /// The size of a packet header in network data.
        /// </summary>
        public const int Size = 5;
            
        /// <summary>
        /// The length of the entire packet, excluding the length which is sizeof(uint) and excluding the MAC.
        /// </summary>
        public uint Length;

        /// <summary>
        /// The length of the padding, this is used to ensure the packet is a multiple of block size.
        /// </summary>
        public byte PaddingLength;

        /// <summary>
        /// Try and parse a packet header from the provided buffer.
        /// </summary>
        /// <param name="buffer">The buffer.</param>
        /// <remarks>This method will not validate the data, such as the minimum 4 byte padding length.</remarks>
        /// <returns>If parsing was successful.</returns>
        public bool TryParse(ReadOnlySpan<byte> buffer)
        {
            if (buffer.Length < 5) {
                return false;
            }

            // make a copy of the length we can modify
            if (BitConverter.IsLittleEndian) {
                Span<byte> lengthBytes = stackalloc byte[4];
                buffer.Slice(0, 4).CopyTo(lengthBytes);
                lengthBytes.Reverse();
                Length = BitConverter.ToUInt32(lengthBytes);
            } else {
                Length = BitConverter.ToUInt32(buffer.Slice(0, 4));
            }

            PaddingLength = buffer[4];

            return true;
        }

        /// <summary>
        /// Try and write the provided header to the buffer.
        /// </summary>
        /// <param name="buffer">The buffer.</param>
        /// <remarks>The buffer must be at least 5 bytes.</remarks>
        /// <returns></returns>
        public bool TryWriteBytes(Span<byte> buffer)
        {
            if (buffer.Length < 5)
                return false;

            // write message length
            BitConverter.TryWriteBytes(buffer.Slice(0, 4), Length);

            // convert to big endian (network order) order if little endian
            if (BitConverter.IsLittleEndian)
                buffer.Slice(0, 4).Reverse();

            // write padding length
            buffer[4] = PaddingLength;

            return true;
        }
    }
}
