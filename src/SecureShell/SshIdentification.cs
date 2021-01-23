using System;
using System.Collections.Generic;
using System.Text;

namespace SecureShell
{
    /// <summary>
    /// Represents SSH2 identification information that is exchanged.
    /// </summary>
    public readonly struct SshIdentification
    {
        /// <summary>
        /// The default identification for this library in client/server mode.
        /// </summary>
        public static readonly SshIdentification Default = new SshIdentification("SFSSH-0.1.0");

        /// <summary>
        /// The software version, cannot contain spaces.
        /// </summary>
        public readonly string SoftwareVersion;

        /// <summary>
        /// The comments.
        /// </summary>
        public readonly string Comments;

        /// <summary>
        /// The protocol version, this field is ignored when writing to other peers.
        /// </summary>
        public readonly string ProtocolVersion;

        /// <summary>
        /// Creates a SSH identification structure.
        /// </summary>
        /// <param name="softwareVersion">The software version.</param>
        public SshIdentification(string softwareVersion)
        {
            SoftwareVersion = softwareVersion;
            Comments = null;
            ProtocolVersion = "2.0";
        }

        /// <summary>
        /// Creates a SSH identification structure.
        /// </summary>
        /// <param name="softwareVersion">The software version.</param>
        /// <param name="comments">The optional comments.</param>
        public SshIdentification(string softwareVersion, string comments)
        {
            SoftwareVersion = softwareVersion;
            Comments = comments;
            ProtocolVersion = "2.0";
        }

        /// <summary>
        /// Creates a SSH identification structure.
        /// </summary>
        /// <param name="protocolVersion">The protocol version.</param>
        /// <param name="softwareVersion">The software version.</param>
        /// <param name="comments">The optional comments.</param>
        public SshIdentification(string protocolVersion, string softwareVersion, string comments)
        {
            SoftwareVersion = softwareVersion;
            Comments = comments;
            ProtocolVersion = protocolVersion;
        }
    }
}
