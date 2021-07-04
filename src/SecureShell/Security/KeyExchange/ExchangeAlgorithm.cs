using SecureShell.Transport;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SecureShell.Security.KeyExchange
{
    /// <summary>
    /// Represents a key exchange algorithm.
    /// </summary>
    public abstract class ExchangeAlgorithm
    {
        /// <summary>
        /// Gets the name of the key exchange algorithm.
        /// </summary>
        public abstract string Name { get; }

        /// <summary>
        /// Resets the algorithm so it can be reused, the implementation can return a new instance if need be.
        /// </summary>
        /// <returns>The reset exchange algorithm.</returns>
        public abstract ExchangeAlgorithm Reset();

        /// <summary>
        /// Called once when an exchange has begun, initialisation logic goes here.
        /// </summary>
        /// <param name="peer">The peer.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns></returns>
        protected internal abstract ValueTask ExchangeAsync(Peer peer, CancellationToken cancellationToken = default);

        /// <summary>
        /// Called when a message has been received which should be processed. If the packet must be used throughout processing and after reading further
        /// packets the implementer MUST convert the packet into a <see cref="MemoryPacket"/> using <see cref="IncomingPacket.ToMemoryPacket"/>.
        /// The implementer must also call <see cref="IncomingPacket.Advance"/> before the method returns.
        /// </summary>
        /// <param name="peer">The peer.</param>
        /// <param name="packet">The packet.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>If the exchange was completed.</returns>
        protected internal abstract ValueTask<bool> ProcessExchangeAsync(Peer peer, IncomingPacket packet, CancellationToken cancellationToken = default);
    }
}
