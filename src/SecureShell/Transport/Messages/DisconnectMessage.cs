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
        public string Description;

        /// <summary>
        /// The language tag as defined by RFC3066.
        /// </summary>
        public string LanguageTag;

        /// <summary>
        /// The decoder for the disconnect message.
        /// </summary>
        public struct Decoder : IMessageDecoder<DisconnectMessage>
        {
            private State _state;

            private uint _stringLength;
            private StringBuilder _stringBuilder;
            private int _stringProgress;

            enum State
            {
                ReasonCode,
                Description,
                LanguageTag
            }

            /// <summary>
            /// Gets or sets if the description should be skipped. If true <see cref="DisconnectMessage.Description"/> will be an empty string.
            /// </summary>
            /// <remarks>This value is not reset by <see cref="Reset"/>.</remarks>
            public bool IgnoreDescription { get; set; }

            /// <summary>
            /// Gets or sets if the language tag should be skipped. If true <see cref="DisconnectMessage.Description"/> will be an empty string.
            /// </summary>
            /// <remarks>This value is not reset by <see cref="Reset"/>.</remarks>
            public bool IgnoreLanguageTag { get; set; }

            /// <inheritdoc/>
            public OperationStatus Decode(ref DisconnectMessage message, ref SequenceReader<byte> reader)
            {
                throw new NotImplementedException();
            }

            /// <inheritdoc/>
            public void Reset()
            {
                _state = State.ReasonCode;
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
                + 4 + (Description == null ? 0 : Encoding.UTF8.GetByteCount(Description))
                + 4 + (LanguageTag == null ? 0 : Encoding.UTF8.GetByteCount(LanguageTag)));
    }
}
