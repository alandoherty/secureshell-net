using System;
using System.Buffers;
using System.Collections.Generic;
using System.Text;

namespace SecureShell.Transport.Protocol
{
    /// <summary>
    /// Defines an interface for encoding/decoding objects in <see cref="MessageBuffer{T}"/> structures.
    /// </summary>
    public interface IBufferConverter<T>
    {
        /// <summary>
        /// Gets the number of bytes required to store a value in a buffer.
        /// </summary>
        /// <param name="val">The value.</param>
        /// <returns>The number of bytes.</returns>
        int GetByteCount(T val);

        /// <summary>
        /// Try and decode a value from the provided sequence. 
        /// </summary>
        /// <param name="sequence">The sequence.</param>
        /// <param name="val">The value output.</param>
        /// <returns>The result of the operation.</returns>
        OperationStatus TryDecode(ReadOnlySequence<byte> sequence, out T val);

        /// <summary>
        /// Try and encode a value to the provided buffer.
        /// </summary>
        /// <param name="buffer">The buffer.</param>
        /// <param name="val">The value.</param>
        /// <param name="bytesWritten">The number of bytes which were written.</param>
        /// <returns>The result of the operation, <see cref="OperationStatus.NeedMoreData"/> is not permitted.</returns>
        OperationStatus TryEncode(Span<byte> buffer, T val, out int bytesWritten);
    }
}
