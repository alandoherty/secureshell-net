using SecureShell.Transport.Protocol;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Text;

namespace SecureShell.Transport.Messages
{
    /// <summary>
    /// The disconnect transport message.
    /// </summary>
    internal struct DisconnectMessage : IPacketMessage<DisconnectMessage>
    {
        /// <summary>
        /// The machine-readable reason why the connection was disconnected.
        /// </summary>
        public uint ReasonCode;

        /// <summary>
        /// The description. 
        /// </summary>
        public MessageBuffer<string> Description;

        /// <summary>
        /// The language tag as defined by RFC3066.
        /// </summary>
        public MessageBuffer<string> LanguageTag;

        /// <summary>
        /// The decoder for the disconnect message.
        /// </summary>
        public struct Decoder : IMessageDecoder<DisconnectMessage>
        {
            /// <inheritdoc/>
            public OperationStatus Decode(ref DisconnectMessage message, ref MessageReader reader)
            {
                reader.Advance(1);
                throw new NotImplementedException();
            }

            /// <inheritdoc/>
            public void Reset()
            {
            }
        }

        /// <summary>
        /// The encoder for the disconnect message.
        /// </summary>
        public struct Encoder
        {

        }

        /// <inheritdoc/>
        public IMessageDecoder<DisconnectMessage> CreateDecoder() => new Decoder();

        /// <inheritdoc/>
        public IMessageEncoder<DisconnectMessage> CreateEncoder() => throw new NotImplementedException();

        /// <inheritdoc/>
        public uint GetByteCount() => (uint)(4
                + 4 + Description.GetByteCount(BufferConverter.StringUtf8)
                + 4 + LanguageTag.GetByteCount(BufferConverter.StringUtf8));
    }
}
