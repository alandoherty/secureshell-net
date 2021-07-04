using System;
using System.Collections.Generic;
using System.Text;

namespace SecureShell.Transport
{
    /// <summary>
    /// Represents a buffer inside a message. This is used to allow zero-copy decoding and single copy encoding of types like strings directly into the outgoing buffer.
    /// </summary>
    public struct MessageBuffer
    {
        enum Contents
        {
            None,
            Buffer,
            String,
        }

        private ReadOnlyMemory<byte> _buffer;
        private object _obj;
        private Contents _contents;

        /// <summary>
        /// Gets the length of the buffers contents.
        /// </summary>
        /// <returns>The byte count.</returns>
        public int GetByteCount()
        {
            if (_contents == Contents.None)
                throw new InvalidOperationException("The message buffer is empty");

            switch (_contents) {
                case Contents.Buffer:
                    return _buffer.Length;
                case Contents.String:
                    return Encoding.UTF8.GetByteCount((string)_obj);
                default:
                    throw new NotImplementedException();
            }
        }

        /// <summary>
        /// Gets the buffer as a newly allocated byte array.
        /// </summary>
        /// <returns></returns>
        public byte[] AsByteArray()
        {
            if (_contents == Contents.None)
                throw new InvalidOperationException("The message buffer is empty");

            switch (_contents) {
                case Contents.Buffer:
                    return _buffer.ToArray();
                case Contents.String:
                    return Encoding.UTF8.GetBytes((string)_obj);
                default:
                    throw new NotImplementedException();
            }
        }

        /// <summary>
        /// Get the buffer as a UTF-8 encoded string.
        /// </summary>
        /// <returns>The string.</returns>
        public string AsString()
        {
            if (_contents == Contents.None)
                throw new InvalidOperationException("The message buffer is empty");

            switch(_contents) {
                case Contents.Buffer:
                    return Encoding.UTF8.GetString(_buffer.Span);
                case Contents.String:
                    return (string)_obj;
                default:
                    throw new NotImplementedException();
            }
        }

        /// <summary>
        /// Try and write bytes to the provided buffer.
        /// </summary>
        /// <param name="buffer">The buffer.</param>
        /// <param name="bytesWritten">The output of bytes written.</param>
        /// <returns>If any of the buffer was copied.</returns>
        public bool TryWriteBytes(Span<byte> buffer, out int bytesWritten)
        {
            if (_contents == Contents.None)
                throw new InvalidOperationException("The message buffer is empty");

            switch (_contents) {
                case Contents.Buffer:
                    if (buffer.Length < _buffer.Length) {
                        bytesWritten = 0;
                        return false;
                    }

                    _buffer.Span.CopyTo(buffer);
                    bytesWritten = buffer.Length;
                    return true;
                case Contents.String:
                    bytesWritten = Encoding.UTF8.GetBytes(((string)_obj).AsSpan(), buffer);
                    return true;
                default:
                    throw new NotImplementedException();
            }
        }

        /// <summary>
        /// Creates a new message buffer from the memory.
        /// </summary>
        /// <param name="buffer">The buffer.</param>
        public MessageBuffer(ReadOnlyMemory<byte> buffer)
        {
            _buffer = buffer;
            _contents = Contents.Buffer;
            _obj = default;
        }

        /// <summary>
        /// Creates a new message buffer from the string.
        /// </summary>
        /// <param name="str">The string.</param>
        public MessageBuffer(string str)
        {
            _buffer = ReadOnlyMemory<byte>.Empty;
            _contents = Contents.String;
            _obj = str;
        }
    }
}
