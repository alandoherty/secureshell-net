﻿using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Text;
using System.Threading.Tasks;

namespace SecureShell.Protocol
{
    /// <summary>
    /// Represents a packet payload.
    /// </summary>
    public interface IPacketMessage<TMessage>
        where TMessage : IPacketMessage<TMessage>
    {
        /// <summary>
        /// Gets the byte count.
        /// </summary>
        /// <returns>The byte count of the message.</returns>
        int GetByteCount();

        /// <summary>
        /// Creates a decoder for this message.
        /// </summary>
        /// <remarks>This will box the resulting object.</remarks>
        /// <returns>The decoder.</returns>
        IMessageDecoder<TMessage> CreateDecoder();
        
        /// <summary>
        /// Creates an encoder for this message.
        /// </summary>
        /// <remarks>This will box the resulting object.</remarks>
        /// <returns>The encoder.</returns>
        IMessageEncoder<TMessage> CreateEncoder();
    }
}
