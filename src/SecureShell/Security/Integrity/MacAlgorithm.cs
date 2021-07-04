using System;
using System.Collections.Generic;
using System.Text;

namespace SecureShell.Security.Integrity
{
    /// <summary>
    /// Represents integrity MAC algorithims and provides the built-ins.
    /// </summary>
    public abstract class MacAlgorithm
    {
        /// <summary>
        /// The none algorithim.
        /// </summary>
        public static NoneMacAlgorithm None = new NoneMacAlgorithm();

        /// <summary>
        /// Try to create a a mac algorithim from name.
        /// </summary>
        /// <param name="name">The SSH name.</param>
        /// <param name="algorithm">The output algorithim.</param>
        /// <returns>If the algorithim is supported.</returns>
        public static bool TryCreateFromName(string name, out MacAlgorithm algorithm)
        {
            if (name.Equals("none", StringComparison.OrdinalIgnoreCase)) {
                algorithm = None; // no create neccessary
                return true;
            } else {
                algorithm = null;
                return false;
            }
        }

        /// <summary>
        /// Gets the size of the integrity data sent with packets.
        /// </summary>
        public abstract int Size { get; }

        /// <summary>
        /// Appends data to be integrity hash for the provided message.
        /// </summary>
        /// <param name="message">The message data.</param>
        /// <param name="outHash">The output data.</param>
        /// <returns>If the output data was large enough and the integrity was computed.</returns>
        public abstract void Append(ReadOnlySpan<byte> message, Span<byte> outHash);

        /// <summary>
        /// Verify that the appended message matches the provided input hash.
        /// </summary>
        /// <param name="inHash">The input hash.</param>
        /// <returns>If the MAC was valid.</returns>
        public abstract bool Verify(ReadOnlySpan<byte> inHash);

        /// <summary>
        /// Resets the hash for the next message.
        /// </summary>
        public abstract void Reset();

        /// <summary>
        /// Creates an instance to be used within a peer. If the algorithim is stateless this may return one instance for every peer.
        /// </summary>
        /// <returns>The algorithim instance.</returns>
        public abstract MacAlgorithm Create();
    }
}
