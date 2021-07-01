using System;
using System.Buffers;
using System.Collections.Generic;
using System.Text;

namespace SecureShell.Transport.Messages
{
    /// <summary>
    /// Represents an empty message with no contents.
    /// </summary>
    public struct EmptyMessage : IPacketMessage<EmptyMessage>
    {
        /// <summary>
        /// The decoder for the empty message.
        /// </summary>
        public struct Decoder : IMessageDecoder<EmptyMessage>
        {
            /// <inheritdoc/>
            public OperationStatus Decode(ref EmptyMessage message, ref SequenceReader<byte> reader) => OperationStatus.Done;

            /// <inheritdoc/>
            public void Reset() { }
        }

        /// <summary>
        /// The encoder for the empty message.
        /// </summary>
        public struct Encoder : IMessageEncoder<EmptyMessage>
        {
            /// <inheritdoc/>
            public bool Encode(in EmptyMessage message, IBufferWriter<byte> writer) => true;

            /// <inheritdoc/>
            public void Reset() { }
        }

        /// <inheritdoc/>
        public IMessageDecoder<EmptyMessage> CreateDecoder() => new Decoder();

        /// <inheritdoc/>
        public IMessageEncoder<EmptyMessage> CreateEncoder() => new Encoder();

        /// <inheritdoc/>
        public uint GetByteCount() => 0U;
    }
}
