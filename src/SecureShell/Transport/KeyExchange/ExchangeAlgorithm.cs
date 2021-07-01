using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SecureShell.Transport.KeyExchange
{
    public abstract class ExchangeAlgorithm
    {
        /// <summary>
        /// Called when an exchange has begun, initialisation logic goes here. The instance MUST reset itself upon receiving this call.
        /// </summary>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns></returns>
        public abstract ValueTask ExchangeAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Called when a message has been received which should be processed. If the packet must be used throughout processing and after reading further
        /// packets the implementer MUST convert the packet into a <see cref="MemoryPacket"/> using <see cref="IncomingPacket.ToMemoryPacket"/>.
        /// The implementer must also call <see cref="IncomingPacket.Advance"/> before the method returns.
        /// </summary>
        /// <param name="header">The message header.</param>
        /// <param name="peer">The peer.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>If the exchange was completed.</returns>
        public abstract ValueTask<bool> ProcessExchangeAsync(IncomingPacket packet, CancellationToken cancellationToken = default);
    }
}
