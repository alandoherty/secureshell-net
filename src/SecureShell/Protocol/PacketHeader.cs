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

        public bool TryParse(ReadOnlySequence<byte> sequence)
        {
            // if too small return false
            if (sequence.Length < 5)
                return false;

            // create a buffer, copy into then parse that buffer
            Span<byte> buffer = stackalloc byte[5];
            sequence.Slice(0, 5)
                .CopyTo(buffer);

            return TryParse(buffer);
        }

        public bool TryParse(ReadOnlySpan<byte> buffer)
        {
           
            return true;
        }

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
