using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SecureShell.Transport.Protocol
{
    /// <summary>
    /// Provides a standard interface to write a message.
    /// </summary>
    /// <typeparam name="TMessage">The message type.</typeparam>
    public interface IMessageEncoder<TMessage>
        where TMessage : IPacketMessage<TMessage>
    {
        /// <summary>
        /// Encodes the message, implementers may choose to request a flush and recall. The message number must be written by the encoder.
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
