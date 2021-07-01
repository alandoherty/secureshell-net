using System;
using System.Buffers;
using System.Collections.Generic;
using System.Text;

namespace SecureShell.Transport
{
    /// <summary>
    /// Provides extensions for packet functionality.
    /// </summary>
    public static class PacketExtensions
    {
        /// <summary>
        /// Try and get the <see cref="MessageNumber"/> from the first byte of the payload.
        /// </summary>
        /// <param name="number">The output message number.</param>
        /// <returns>If the number could be decoded.</returns>
        public static bool TryGetMessageNumber(this MemoryPacket packet, out MessageNumber number)
        {
            if (packet.Payload.Length == 0) {
                number = default;
                return false;
            }

            number = (MessageNumber)packet.Payload.FirstSpan[0];
            return true;
        }

        /// <summary>
        /// Try and get the <see cref="MessageNumber"/> from the first byte of the payload.
        /// </summary>
        /// <param name="number">The output message number.</param>
        /// <returns>If the number could be decoded.</returns>
        public static bool TryGetMessageNumber(this IncomingPacket packet, out MessageNumber number)
        {
            if (packet.Payload.Length == 0) {
                number = default;
                return false;
            }

            number = (MessageNumber)packet.Payload.FirstSpan[0];
            return true;
        }

        /// <summary>
        /// Try and decode the specified message from the packet.
        /// </summary>
        /// <typeparam name="TMessage">The message type.</typeparam>
        /// <typeparam name="TMessageDecoder">The message decoder.</typeparam>
        /// <param name="packet">The packet.</param>
        /// <param name="msg">The message.</param>
        /// <param name="decoder">The decoder.</param>
        /// <returns>If decoding was successful.</returns>
        public static bool TryDecode<TMessage, TMessageDecoder>(this MemoryPacket packet, out TMessage msg, TMessageDecoder decoder = default)
            where TMessage : IPacketMessage<TMessage>
            where TMessageDecoder : IMessageDecoder<TMessage>
        {
            SequenceReader<byte> reader = new SequenceReader<byte>(packet.Payload);
            reader.Advance(1);
            return TryDecode(ref reader, out msg, decoder);
        }

        /// <summary>
        /// Try and decode the specified message from the packet, this message will only be valid until the <see cref="IncomingPacket"/> is advanced.
        /// </summary>
        /// <typeparam name="TMessage">The message type.</typeparam>
        /// <typeparam name="TMessageDecoder">The message decoder.</typeparam>
        /// <param name="packet">The packet.</param>
        /// <param name="msg">The message.</param>
        /// <param name="decoder">The decoder.</param>
        /// <returns>If decoding was successful.</returns>
        public static bool TryDecode<TMessage, TMessageDecoder>(this IncomingPacket packet, out TMessage msg, TMessageDecoder decoder = default)
            where TMessage : IPacketMessage<TMessage>
            where TMessageDecoder : IMessageDecoder<TMessage>
        {
            SequenceReader<byte> reader = new SequenceReader<byte>(packet.Payload);
            reader.Advance(1);
            return TryDecode(ref reader, out msg, decoder);
        }

        private static bool TryDecode<TMessage, TMessageDecoder>(ref SequenceReader<byte> reader, out TMessage msg, TMessageDecoder decoder = default)
            where TMessage : IPacketMessage<TMessage>
            where TMessageDecoder : IMessageDecoder<TMessage>
        {
            msg = default;
            
            switch(decoder.Decode(ref msg, ref reader)) {
                case OperationStatus.Done:
                    return true;
                case OperationStatus.InvalidData:
                    return false;
                case OperationStatus.NeedMoreData:
                    return false;
                default:
                    throw new Exception("The decoder returned an invalid status");
            }
        }
    }
}
