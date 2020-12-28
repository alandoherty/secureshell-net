using System;
using System.Buffers;
using System.Collections.Generic;
using System.Text;

namespace SecureShell.Protocol
{
    /// <summary>
    /// Provides a standard interface to write a message.
    /// </summary>
    /// <typeparam name="TMessage">The message type.</typeparam>
    public interface IMessageEncoder<TMessage>
        where TMessage : IPacketMessage<TMessage>
    {
        /// <summary>
        /// Encodes part of the message.
        /// </summary>
        /// <param name="message">The message.</param>
        /// <param name="writer">The writer.</param>
        /// <returns>When the underlying data should be flushed, if true the message has entirely been encoded otherwise the value is false.</returns>
        bool Encode(in TMessage message, IBufferWriter<byte> writer);

        /// <summary>
        /// Resets the encoder, allowing it to be reused.
        /// </summary>
        void Reset();
    }
}
