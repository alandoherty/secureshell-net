using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SecureShell.Transport
{
    /// <summary>
    /// Represents a packet that has been read into internal buffers in a <see cref="SshPeer"/>. 
    /// </summary>
    public struct IncomingPacket : IDisposable
    {
        private SequencePosition _advanceTo;

        /// <summary>
        /// The packet header.
        /// </summary>
        public readonly PacketHeader Header;

        /// <summary>
        /// The message payload.
        /// </summary>
        public readonly ReadOnlySequence<byte> Payload;

        /// <summary>
        /// The peer which received the packet.
        /// </summary>
        public readonly SshPeer Peer;

        /// <summary>
        /// Advances the peer past the packet, any decoded messages will reference invalid buffers once called. Use 
        /// </summary>
        /// <returns></returns>
        public void Advance()
        {
            if (_advanceTo.Equals(default)) {
                throw new InvalidOperationException("The packet has already been advanced on the peer");
            }

            Peer.AdvanceTo(_advanceTo);
            _advanceTo = default;
        }

        /// <summary>
        /// Creates a <see cref="MemoryPacket"/>, allocating and copying data into new buffers. This can be used to extend the lifetime
        /// of a packet, you must still call <see cref="Advance"/> to move the reader forward.
        /// </summary>
        /// <returns>The memory packet.</returns>
        public MemoryPacket ToMemoryPacket()
        {
            return new MemoryPacket(Header, Payload.ToArray().AsMemory());
        }

        /// <summary>
        /// Advances the packet, see <see cref="Advance"/>.
        /// </summary>
        public void Dispose()
        {
            Advance();
        }

        internal IncomingPacket(PacketHeader header, ReadOnlySequence<byte> payload, SshPeer peer, SequencePosition advanceTo)
        {
            Header = header;
            Payload = payload;
            _advanceTo = advanceTo;
            Peer = peer;
        }
    }
}
