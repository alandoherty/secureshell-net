using System;
using System.Collections.Generic;
using System.Text;

namespace SecureShell
{
    /// <summary>
    /// Represents the state of the peer, all peers begin in the <see cref="IdentificationExchange"/> state.
    /// </summary>
    public enum PeerState
    {
        /// <summary>
        /// The peer is exchanging identification/version.
        /// </summary>
        IdentificationExchange,

        /// <summary>
        /// The peer is exchanging or re-exchanging keys.
        /// </summary>
        KeyExchange,

        /// <summary>
        /// The peer is open and application data can be sent.
        /// </summary>
        Open,

        /// <summary>
        /// The peer is closing.
        /// </summary>
        Closing,

        /// <summary>
        /// The peer has closed, further data cannot be sent.
        /// </summary>
        Closed
    }
}
