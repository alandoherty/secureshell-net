﻿using System;
using System.Buffers;
using System.Collections.Generic;
using System.Text;

namespace SecureShell.Transport
{
    /// <summary>
    /// Provides a standard interface to read a message.
    /// </summary>
    /// <typeparam name="TMessage">The message type.</typeparam>
    public interface IMessageDecoder<TMessage>
        where TMessage : IPacketMessage<TMessage>
    {
        /// <summary>
        /// Decodes the message, the entire message is available. Implementers must handle the message number byte.
        /// </summary>
        /// <param name="message">The message.</param>
        /// <param name="reader">The sequence reader.</param>
        /// <returns>When as much data as possible has been read, true if more is required or false if all data has been decoded.</returns>
        OperationStatus Decode(ref TMessage message, ref SequenceReader<byte> reader);
        
        /// <summary>
        /// Resets the decoder, allowing it to be reused.
        /// </summary>
        void Reset();
    }
}
