using System;
using System.Collections.Generic;
using System.Text;

namespace SecureShell.Transport
{
    /// <summary>
    /// The message header.
    /// </summary>
    public struct MessageHeader
    {
        /// <summary>
        /// The size of the message header.
        /// </summary>
        public const int Size = PacketHeader.Size + 1;

        /// <summary>
        /// The packet header.
        /// </summary>
        public PacketHeader Header;

        /// <summary>
        /// The message number.
        /// </summary>
        public MessageNumber Number;
    }
}
