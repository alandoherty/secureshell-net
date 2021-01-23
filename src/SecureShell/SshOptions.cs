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
    }
}