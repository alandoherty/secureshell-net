using System.Buffers;

namespace SecureShell.Transport
{
    /// <summary>
    /// Implements extensions to <see cref="SequenceReader{T}"/> for the SSH protocol.
    /// </summary>
    public static class SequenceReaderExtensions
    {
        /// <summary>
        /// Try and read a packet header from the sequence reader.
        /// </summary>
        /// <param name="reader">The reader.</param>
        /// <param name="header">The header.</param>
        /// <returns>If the header could be read.</returns>
        public static bool TryRead(this ref SequenceReader<byte> reader, out PacketHeader header)
        {
            // check if enough bytes exist
            if (reader.Remaining < 5) {
                header = default;
                return false;
            }

            // read the 32-bit length as network byte order
            if (!reader.TryReadBigEndian(out int length)) {
                header = default;
                return false;
            }

            // read the padding length, must always be 4 but we don't validate here
            if (!reader.TryRead(out byte paddingLength)) {
                header = default;
                return false;
            }

            // set data, we're all good
            header = default;
            header.PaddingLength = paddingLength;
            header.Length = (uint)length;
            return true;
        }
    }
}