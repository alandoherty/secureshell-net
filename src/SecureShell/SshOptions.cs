using SecureShell.Security.KeyExchange;
using System;
using System.Collections.Generic;

namespace SecureShell
{
    /// <summary>
    /// Defines the options for a SSH peer.
    /// </summary>
    public sealed class SshOptions
    {
        // To save allocations when no options provided we use a shared but mutable instance that wont be exposed
        internal static readonly SshOptions DefaultInstance = new SshOptions();

        /// <summary>
        /// The default SSH options.
        /// </summary>
        public static SshOptions Default { get; } = new SshOptions();

        /// <summary>
        /// The default SSH options with older algorithms and safer values, only use if required.
        /// </summary>
        private static SshOptions Compatability => throw new NotImplementedException(); //TODO

        /// <summary>
        /// The timeout for exchanging identification.
        /// </summary>
        public TimeSpan? IdentificationExchangeTimeout { get; set; } = TimeSpan.FromSeconds(5);

        /// <summary>
        /// The enabled key exchange algorithms in order of preferred usage.
        /// </summary>
        public IEnumerable<ExchangeAlgorithm> KeyExchangeAlgorithms { get; set; } = new ExchangeAlgorithm[] {
            new DiffieHellmanGroupExchangeAlgorithm()
        };

        /// <summary>
        /// The maximum packet size the peer will accept, must be 35000 or greater.
        /// </summary>
        internal int MaximumPacketSize { get; set; } = 131072;

        internal void ThrowIfInvalid()
        {
            if (MaximumPacketSize < 35000)
                throw new InvalidOperationException("The maximum packet size cannot be smaller than 35,000 bytes");
        }
    }
}