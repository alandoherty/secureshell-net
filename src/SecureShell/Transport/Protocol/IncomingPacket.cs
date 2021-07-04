using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SecureShell.Transport.Protocol
{
    /// <summary>
    /// Represents a packet that has been read into internal buffers in a <see cref="SecureShell.Peer"/>. 
    /// </summary>
    public struct IncomingPacket : IDisposable
    {
        private ReadOnlySequence<byte> _payload;
        private SequencePosition _advanceTo;

        /// <summary>
        /// The packet header.
        /// </summary>
        public readonly PacketHeader Header { get; }

        /// <summary>
        /// The message payload.
        /// </summary>
        public readonly ReadOnlySequence<byte> Payload {
            get {
                if (Peer.State == PeerState.Closed || Peer.State == PeerState.Closing) {
                    throw new InvalidOperationException("The peer is not either closing or closed and buffers are inaccessible");
                }

                return _payload;
            }
        }

        /// <summary>
        /// The peer which received the packet.
        /// </summary>
        public readonly Peer Peer { get; }

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
        /// Creates a <see cref="MemoryPacket>"/>, copying data into the provided buffer. This can be used to extend the lifetime
        /// of a packet, you must still call <see cref="Advance"/> to move the reader forward.
        /// </summary>
        /// <param name="buffer">The destination buffer.</param>
        /// <returns>The memory packet.</returns>
        public MemoryPacket ToMemoryPacket(Memory<byte> buffer)
        {
            if (buffer.Length < Payload.Length) {
                throw new ArgumentOutOfRangeException(nameof(buffer), "The provided buffer is not large enough for the packet payload");
            }

            Payload.CopyTo(buffer.Span);
            return new MemoryPacket(Header, buffer.Slice(0, (int)Payload.Length));
        }

        /// <summary>
        /// Advances the packet, see <see cref="Advance"/>.
        /// </summary>
        public void Dispose()
        {
            Advance();
        }

        internal IncomingPacket(PacketHeader header, ReadOnlySequence<byte> payload, Peer peer, SequencePosition advanceTo)
        {
            Header = header;
            _payload = payload;
            _advanceTo = advanceTo;
            Peer = peer;
        }
    }
}
