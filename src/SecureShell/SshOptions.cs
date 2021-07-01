using System;

namespace SecureShell
{
    /// <summary>
    /// Defines the options for a SSH peer.
    /// </summary>
    public sealed class SshOptions
    {
        /// <summary>
        /// The default SSH options.
        /// </summary>
        internal static readonly SshOptions Default = new SshOptions() {
            
        };

        /// <summary>
        /// The timeout for exchanging identification.
        /// </summary>
        public TimeSpan? IdentificationExchangeTimeout { get; set; } = TimeSpan.FromSeconds(5);

        /// <summary>
        /// The maximum packet size the peer will accept, must be 35000 or greater.
        /// </summary>
        internal int MaximumPacketSize { get; set; } = 35000;
    }
}