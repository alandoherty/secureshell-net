using System;
using System.Buffers;
using System.Collections.Generic;
using System.Numerics;
using System.Text;

namespace SecureShell.Transport.Protocol
{
    /// <summary>
    /// Provides the common buffer converters.
    /// </summary>
    public static class BufferConverter
    {
        /// <summary>
        /// A big-endian unsigned <see cref="System.Numerics.BigInteger"/>.
        /// </summary>
        public static IBufferConverter<BigInteger> BigInteger { get; } = new BigIntegerConverter();

        /// <summary>
        /// A UTF-8 encoded string.
        /// </summary>
        public static IBufferConverter<string> StringUtf8 { get; } = new StringConverter(Encoding.UTF8);

        /// <summary>
        /// An ASCII encoded string.
        /// </summary>
        public static IBufferConverter<string> StringASCII { get; } = new StringConverter(Encoding.ASCII);

        /// <summary>
        /// A <see cref="ReadOnlyMemory"/>
        /// </summary>
        public static IBufferConverter<ReadOnlyMemory<byte>> ReadOnlyMemory { get; } = new ReadOnlyMemoryConverter();

        class ReadOnlyMemoryConverter : IBufferConverter<ReadOnlyMemory<byte>>
        {
            public int GetByteCount(ReadOnlyMemory<byte> val)
            {
                return val.Length;
            }

            public OperationStatus TryDecode(ReadOnlySequence<byte> sequence, out ReadOnlyMemory<byte> val)
            {
                byte[] arr = new byte[(int)sequence.Length];
                sequence.CopyTo(arr.AsSpan());
                val = new ReadOnlyMemory<byte>(arr);

                return OperationStatus.Done;
            }

            public OperationStatus TryEncode(Span<byte> buffer, ReadOnlyMemory<byte> val, out int bytesWritten)
            {
                int byteCount = GetByteCount(val);

                if (buffer.Length < byteCount) {
                    bytesWritten = 0;
                    return OperationStatus.DestinationTooSmall;
                }

                if (!val.Span.TryCopyTo(buffer))
                    throw new Exception("Unexpected error occured writing ReadOnlyMemory<byte> to buffer");

                bytesWritten = val.Length;
                return OperationStatus.Done;
            }
        }

        class BigIntegerConverter : IBufferConverter<BigInteger>
        {
            public int GetByteCount(BigInteger val)
            {
                return val.GetByteCount();
            }

            public OperationStatus TryDecode(ReadOnlySequence<byte> sequence, out BigInteger val)
            {
                if (sequence.IsSingleSegment) {
                    val = new BigInteger(sequence.FirstSpan, false, true);
                } else {
                    Span<byte> bytes = stackalloc byte[(int)sequence.Length];
                    sequence.CopyTo(bytes);
                    val = new BigInteger(sequence.FirstSpan, false, true);
                }

                return OperationStatus.Done;
            }

            public OperationStatus TryEncode(Span<byte> buffer, BigInteger val, out int bytesWritten)
            {
                int byteCount = GetByteCount(val);

                if (buffer.Length < byteCount) {
                    bytesWritten = 0;
                    return OperationStatus.DestinationTooSmall;
                }

                if (!val.TryWriteBytes(buffer, out bytesWritten, false, true))
                    throw new Exception("Unexpected error occured writing BigInteger to buffer");

                return OperationStatus.Done;
            }
        }

        class StringConverter : IBufferConverter<string>
        {
            private Encoding _encoding;

            public StringConverter(Encoding encoding)
            {
                _encoding = encoding;
            }

            public int GetByteCount(string val)
            {
                return _encoding.GetByteCount(val);
            }

            public OperationStatus TryDecode(ReadOnlySequence<byte> sequence, out string val)
            {
                if (sequence.IsSingleSegment) {
                    val = _encoding.GetString(sequence.FirstSpan);
                    return OperationStatus.Done;
                } else {
#if NET5_0
                    val = _encoding.GetString(in sequence);
                    return OperationStatus.Done;
#else

                    // this could be more efficient but hey, use .NET 5 then
                    byte[] arr = ArrayPool<byte>.Shared.Rent((int)sequence.Length);

                    try {
                        sequence.CopyTo(arr.AsSpan(0, (int)sequence.Length));
                        val = _encoding.GetString(arr.AsSpan(0, (int)sequence.Length));
                        return OperationStatus.Done;
                    } finally {
                        ArrayPool<byte>.Shared.Return(arr, true);
                    }
#endif
                }
            }

            public OperationStatus TryEncode(Span<byte> buffer, string val, out int bytesWritten)
            {
                //TODO: this could be done more efficently
                int byteCount = _encoding.GetByteCount(val);

                if (_encoding.GetBytes(val.AsSpan(), buffer) != byteCount) {
                    bytesWritten = 0;
                    return OperationStatus.DestinationTooSmall;
                }

                bytesWritten = _encoding.GetBytes(val.AsSpan(), buffer);
                return OperationStatus.Done;
            }
        }
    }
}
