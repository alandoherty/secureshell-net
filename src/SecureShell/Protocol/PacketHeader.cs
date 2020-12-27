using System;
using System.Buffers;
using System.Collections.Generic;
using System.Text;

namespace BattleCrate.Filesystem.Ssh.Protocol
{
    /// <summary>
    /// Represents a packet header structure.
    /// </summary>
    public struct PacketHeader
    {
        /// <summary>
        /// A disconnect request.
        /// </summary>
        public const byte SSH_MSG_DISCONNECT = 1;

        /// <summary>
        /// Ignore, used for debugging or to add dummy packets for cryptographic purposes.
        /// </summary>
        public const byte SSH_MSG_IGNORE = 2;

        /// <summary>
        /// Sent for misunderstood messages.
        /// </summary>
        public const byte SSH_MSG_UNIMPLEMENTED = 3;

        /// <summary>
        /// Debug message to potentially be shown to user.
        /// </summary>
        public const byte SSH_MSG_DEBUG = 4;

        /// <summary>
        /// Service request.
        /// </summary>
        public const byte SSH_MSG_SERVICE_REQUEST = 5;

        /// <summary>
        /// Service acceptance result.
        /// </summary>
        public const byte SSH_MSG_SERVICE_ACCEPT = 6;

        /// <summary>
        /// Initialization of key exchange.
        /// </summary>
        public const byte SSH_MSG_KEXINIT = 20;

        /// <summary>
        /// New keys to be used onward.
        /// </summary>
        public const byte SSH_MSG_NEWKEYS = 21;

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
            // if little endian reverse from network byte order (big endian)
            Span<byte> lengthBytes = stackalloc byte[4];
            buffer.Slice(0, 4)
                .CopyTo(lengthBytes);

            if (BitConverter.IsLittleEndian)
                lengthBytes.Reverse();

            Length = BitConverter.ToUInt32(lengthBytes);
            PaddingLength = buffer[4];
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
