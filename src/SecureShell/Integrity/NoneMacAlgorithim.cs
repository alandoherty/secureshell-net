using System;
using System.Collections.Generic;
using System.Text;

namespace BattleCrate.Filesystem.Ssh.Integrity
{
    /// <summary>
    /// Represents the `none` algorithim, performs no integrity.
    /// </summary>
    public sealed class NoneMacAlgorithim : MacAlgorithim
    {
        /// <summary>
        /// Gets the size, which is always zero.
        /// </summary>
        public override int Size => 0;

        /// <inheritdoc/>
        public override void Append(ReadOnlySpan<byte> message, Span<byte> outHash)
        {
        }

        /// <inheritdoc/>
        public override MacAlgorithim Create()
        {
            return this;
        }

        /// <inheritdoc/>
        public override void Reset()
        {
        }

        /// <inheritdoc/>
        public override bool Verify(ReadOnlySpan<byte> inHash)
        {
            return true;
        }
    }
}
