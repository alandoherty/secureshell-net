using System;
using System.Collections.Generic;
using System.Text;

namespace BattleCrate.Filesystem.Ssh
{
    /// <summary>
    /// Defines the peer mode.
    /// </summary>
    public enum PeerMode
    {
        /// <summary>
        /// The peer is a client.
        /// </summary>
        Client,

        /// <summary>
        /// The peer is a serverside connection.
        /// </summary>
        Server
    }
}
