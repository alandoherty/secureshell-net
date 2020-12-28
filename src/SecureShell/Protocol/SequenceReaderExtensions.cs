using System.Buffers;

namespace SecureShell.Protocol
{
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
            if (reader.Length < 5) {
                header = default;
                return false;
            }

            reader.TryReadBigEndian(out int length);
            reader.TryRead(out byte paddingLength);

            header = default;
            header.PaddingLength = paddingLength;
            header.Length = (uint)length;
            return true;
        }
    }
}