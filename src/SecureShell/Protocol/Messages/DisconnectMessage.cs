using System;
using System.Buffers;
using System.Collections.Generic;
using System.Text;

namespace SecureShell.Protocol.Messages
{
    /// <summary>
    /// The disconnect transport message.
    /// </summary>
    public struct DisconnectMessage : IPacketMessage<DisconnectMessage>
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
            private uint? _descriptionLength;
            private uint? _languageTagLength;

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
            public bool Decode(ref DisconnectMessage message, ref SequenceReader<byte> reader)
            {
                throw new NotImplementedException();
            }

            /// <inheritdoc/>
            public void Reset()
            {
                throw new NotImplementedException();
            }
        }

        /// <summary>
        /// The encoder for the disconnect message.
        /// </summary>
        public struct Encoder
        {

        }

        /// <inheritdoc/>
        public IMessageDecoder<DisconnectMessage> CreateDecoder()
        {
            return new Decoder();
        }

        /// <inheritdoc/>
        public IMessageEncoder<DisconnectMessage> CreateEncoder()
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc/>
        public int GetByteCount()
        {
            return 4
                + 4 + (Description == null ? 0 : Encoding.UTF8.GetByteCount(Description))
                + 4 + (LanguageTag == null ? 0 : Encoding.UTF8.GetByteCount(LanguageTag));
        }
    }
}
