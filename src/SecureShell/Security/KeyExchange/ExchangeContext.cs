using SecureShell.Transport;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Text;

namespace SecureShell.Security.KeyExchange
{
    /// <summary>
    /// Represents a key exchange context, lifetime is the full key exchange.
    /// </summary>
    public struct ExchangeContext
    {
        /// <summary>
        /// The peer.
        /// </summary>
        public Peer Peer { get; internal set; }

        /// <summary>
        /// The client identification.
        /// </summary>
        public SshIdentification ClientIdentification { get; internal set; }

        /// <summary>
        /// The server identification.
        /// </summary>
        public SshIdentification ServerIdentification { get; internal set; }

        /// <summary>
        /// The key initialization payload received from the client.
        /// </summary>
        public ReadOnlyMemory<byte> ClientInitPayload { get; internal set; }

        /// <summary>
        /// The key initialization payload received from the server.
        /// </summary>
        public ReadOnlyMemory<byte> ServerInitPayload { get; internal set; }
    }
}
