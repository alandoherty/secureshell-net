using System;
using System.Buffers;
using System.Collections.Generic;
using System.Text;

namespace SecureShell.Transport
{
    /// <summary>
    /// Represents a packet that has been moved into seperate memory.
    /// </summary>
    public readonly struct MemoryPacket
    {
        /// <summary>
        /// The packet header.
        /// </summary>
        public readonly PacketHeader Header;

        /// <summary>
        /// The message payload.
        /// </summary>
        public readonly ReadOnlySequence<byte> Payload;

        /// <summary>
        /// The memory that backs this 
        /// </summary>
        public readonly Memory<byte> Memory;

        internal MemoryPacket(PacketHeader header, Memory<byte> memory)
        {
            Header = header;
            Payload = new ReadOnlySequence<byte>(memory);
            Memory = memory;
        }
    }
}
