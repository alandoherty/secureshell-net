using System;
using System.Buffers;
using System.Collections.Generic;
using System.Numerics;
using System.Text;

namespace SecureShell.Transport.Protocol
{
    /// <summary>
    /// Provides a wrapper for reading message payloads.
    /// </summary>
    public ref struct MessageReader
    {
        //TODO: make private
        internal SequenceReader<byte> Reader;

        /// <summary>
        /// Gets the remaining data on the reader.
        /// </summary>
        public int Remaining => (int)Reader.Remaining;

        /// <summary>
        /// Advance the reader by the provided byte count.
        /// </summary>
        /// <param name="count">The byte count.</param>
        public void Advance(int count)
        {
            Reader.Advance(count);
        }

        /// <summary>
        /// Try and read a byte from the message.
        /// </summary>
        /// <param name="val">The value.</param>
        /// <returns>If the value was read.</returns>
        public bool TryRead(out byte val)
        {
            return Reader.TryRead(out val);
        }

        /// <summary>
        /// Try and read a byte from the message.
        /// </summary>
        /// <param name="value">The value.</param>
        /// <returns>If the value was read.</returns>
        public bool TryRead(out int val)
        {
            return Reader.TryReadBigEndian(out val);
        }

        /// <summary>
        /// Try and read a byte from the message.
        /// </summary>
        /// <param name="value">The value.</param>
        /// <returns>If the value was read.</returns>
        public bool TryRead(out long val)
        {
            return Reader.TryReadBigEndian(out val);
        }

        public bool TryRead(out PacketHeader b)
        {
            return Reader.TryRead(out b);
        }

        public OperationStatus TryRead(out MessageBuffer buffer)
        {
            if (Reader.Remaining < 4) {
                buffer = default;
                return OperationStatus.NeedMoreData;
            }

            if (!Reader.TryReadBigEndian(out int length)) {
                buffer = default;
                return OperationStatus.NeedMoreData;
            }

            if (Reader.Remaining < length) {
                buffer = default;
                return OperationStatus.NeedMoreData;
            }

            buffer = new MessageBuffer(Reader.Sequence.Slice(Reader.Position, length));
            Reader.Advance(length);
            return OperationStatus.Done;
        }

        public MessageReader(ReadOnlySequence<byte> sequence)
        {
            Reader = new SequenceReader<byte>(sequence);
        }
    }
}
