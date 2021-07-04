using System;
using System.Buffers;
using System.Collections.Generic;
using System.Text;

namespace SecureShell.Transport.Messages
{
    /// <summary>
    /// Represents a generic message with an optional message number.
    /// </summary>
    public struct GenericMessage : IPacketMessage<GenericMessage>
    {
        /// <summary>
        /// The optional message number.
        /// </summary>
        public MessageNumber? Number;

        /// <summary>
        /// The decoder for the empty message.
        /// </summary>
        public struct Decoder : IMessageDecoder<GenericMessage>
        {
            /// <inheritdoc/>
            public OperationStatus Decode(ref GenericMessage message, ref SequenceReader<byte> reader)
            {
                if (reader.TryRead(out byte msgNum)) {
                    message.Number = (MessageNumber)msgNum;
                }
               
                return OperationStatus.Done;
            }

            /// <inheritdoc/>
            public void Reset() { }
        }

        /// <summary>
        /// The encoder for the empty message.
        /// </summary>
        public struct Encoder : IMessageEncoder<GenericMessage>
        {
            /// <inheritdoc/>
            public bool Encode(in GenericMessage message, IBufferWriter<byte> writer)
            {
                if (message.Number != null) {
                    Span<byte> bytes = writer.GetSpan(1);
                    bytes[0] = (byte)message.Number;
                    writer.Advance(1);
                }

                return true;
            }

            /// <inheritdoc/>
            public void Reset() { }
        }

        /// <inheritdoc/>
        public IMessageDecoder<GenericMessage> CreateDecoder() => new Decoder();

        /// <inheritdoc/>
        public IMessageEncoder<GenericMessage> CreateEncoder() => new Encoder();

        /// <inheritdoc/>
        public uint GetByteCount() => Number.HasValue ? 0U : 1U;
    }
}
