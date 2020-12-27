using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Text;
using System.Threading.Tasks;

namespace BattleCrate.Filesystem.Ssh.Protocol
{
    /// <summary>
    /// Represents a packet payload.
    /// </summary>
    public interface IPacketMessage<TMessage>
    {
        /// <summary>
        /// Write the message to the writer.
        /// </summary>
        /// <param name="writer">The writer.</param>
        /// <returns></returns>
        ValueTask WriteAsync(PipeWriter writer);

        /// <summary>
        /// Read the message from the reader.
        /// </summary>
        /// <param name="reader">The reader.</param>
        /// <returns></returns>
        ValueTask ReadAsync(PipeReader reader);

        /// <summary>
        /// Gets the byte count.
        /// </summary>
        /// <returns>The byte count of the message.</returns>
        int GetByteCount();
    }
}
