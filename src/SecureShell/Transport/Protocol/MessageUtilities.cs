using System;
using System.Buffers;
using System.Collections.Generic;
using System.Text;

namespace SecureShell.Transport.Protocol
{
    static class MessageUtilities
    {
        /// <summary>
        /// Encodes the payload into a newly allocated byte array.
        /// </summary>
        /// <typeparam name="TMessage">The message type.</typeparam>
        /// <typeparam name="TEncoder">The encoder for the message.</typeparam>
        /// <param name="msg">The message to encode.</param>
        /// <param name="encoder">The encoder.</param>
        /// <returns>The read only memory slice on the array.</returns>
        public static ReadOnlyMemory<byte> MessageToMemory<TMessage, TEncoder>(in TMessage msg, TEncoder encoder = default)
            where TMessage : IPacketMessage<TMessage>
            where TEncoder : IMessageEncoder<TMessage>
        {
            ArrayBufferWriter<byte> arrayBufferWriter = new ArrayBufferWriter<byte>((int)msg.GetByteCount());
            encoder.Encode(in msg, arrayBufferWriter);
            return arrayBufferWriter.WrittenMemory;
        }
    }
}
