using System;
using System.Buffers;
using System.Collections.Generic;
using System.Numerics;
using System.Text;

namespace SecureShell.Transport.Protocol
{
    /// <summary>
    /// Represents a string/mpint buffer inside a message. This is used to allow zero-copy decoding and single copy encoding of strings into the outgoing buffer.
    /// </summary>
    public struct MessageBuffer<T>
    {
        private ReadOnlySequence<byte> _sequence;
        private T _val;
        private bool _hasVal;

        /// <summary>
        /// Gets the sequence behind this buffer, 
        /// </summary>
        public ReadOnlySequence<byte> Sequence => _sequence;

        /// <summary>
        /// Gets if this buffer has a value within or just represents an undecoded buffer.
        /// </summary>
        public bool HasValue => _hasVal;

        /// <summary>
        /// Gets the number of bytes in the value.
        /// </summary>
        /// <returns>The byte count.</returns>
        public int GetByteCount(IBufferConverter<T> converter = null)
        {
            if (!_hasVal)
                return (int)_sequence.Length;

            if (converter == null)
                throw new InvalidOperationException("Converter must be provided for buffer with value");

            return converter.GetByteCount(_val);
        }

        public OperationStatus TryWriteBytes(Span<byte> buffer, IBufferConverter<T> converter, out int bytesWritten)
        {
            if (!_hasVal)
                throw new InvalidOperationException("The buffer does not contain a value to write");

            return converter.TryEncode(buffer, _val, out bytesWritten);
        }

        public OperationStatus TryGet(out T val, IBufferConverter<T> converter = null)
        {
            if (_hasVal) {
                val = _val;
                return OperationStatus.Done;
            }

            if (converter == null)
                throw new InvalidOperationException("Converter must be provided for buffer without value");

            return converter.TryDecode(Sequence, out val);
        }

        public void Get(out T val, IBufferConverter<T> converter = null)
        {
            OperationStatus status = TryGet(out val, converter);

            if (status == OperationStatus.Done)
                return;

            if (status == OperationStatus.DestinationTooSmall) {
                throw new Exception("Converter decode returned DestinationTooSmall");
            } else if (status == OperationStatus.InvalidData) {
                throw new Exception("Converter decode returned InvalidData");
            } else if (status == OperationStatus.NeedMoreData) {
                throw new Exception("Converter decode returned NeedMoreData");
            } else {
                throw new Exception("Converter decode returned unexpected error");
            }
        }

        /// <summary>
        /// Creates a new message buffer from the memory.
        /// </summary>
        /// <param name="sequence">The sequence.</param>
        public MessageBuffer(ReadOnlySequence<byte> sequence)
        {
            _sequence = sequence;
            _val = default;
            _hasVal = false;
        }

        /// <summary>
        /// Creates a new message buffer from a value.
        /// </summary>
        /// <param name="val">The value.</param>
        public MessageBuffer(T val)
        {
            _sequence = default;
            _val = val;
            _hasVal = true;
        }
    }
}
