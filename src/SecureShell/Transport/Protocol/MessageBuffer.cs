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
    public struct MessageBuffer
    {
        private ReadOnlySequence<byte> _buffer;
        private object _obj;

        /// <summary>
        /// Gets the length of the buffers contents.
        /// </summary>
        /// <returns>The byte count.</returns>
        public int GetByteCount()
        {
            if (_obj == null) {
                return (int)_buffer.Length;
            } else {
                if (_obj is string str) {
                    return Encoding.UTF8.GetByteCount(str);
                } else if (_obj is BigInteger bigInt) {
                    return bigInt.GetByteCount();
                } else {
                    throw new NotImplementedException();
                }
            }
        }

        /// <summary>
        /// Gets the buffer as a newly allocated byte array.
        /// </summary>
        /// <returns></returns>
        public byte[] AsByteArray()
        {
            if (_obj == null) {
                return _buffer.ToArray();
            } else {
                if (_obj is string str) {
                    return Encoding.UTF8.GetBytes(str);
                } else if (_obj is BigInteger bigInt) {
                    return bigInt.ToByteArray();
                } else {
                    throw new NotImplementedException();
                }
            }
        }

        /// <summary>
        /// Get the buffer as a UTF-8 encoded string.
        /// </summary>
        /// <returns>The string.</returns>
        public string AsString()
        {
            if (_obj == null) {
                if (_buffer.Length == 0)
                    return string.Empty;

                if (_buffer.IsSingleSegment) {
                    return Encoding.UTF8.GetString(_buffer.FirstSpan);
                } else {
                    //TODO: more efficient thing can probably be done here
                    return Encoding.UTF8.GetString(_buffer.ToArray());
                }
            } else {
                if (_obj is string str) {
                    return str;
                } else if (_obj is BigInteger bigInt) {
                    throw new InvalidOperationException("The buffer represents a big integer and cannot be converted to a string");
                } else {
                    throw new NotImplementedException();
                }
            }
        }

        /// <summary>
        /// Gets the buffer as a BigInteger.
        /// </summary>
        /// <param name="isUnsigned">If the big integer is unsigned, default true.</param>
        /// <param name="isBigEndian">If the big integer is big endian, default true.</param>
        /// <returns></returns>
        public BigInteger AsBigInteger(bool isUnsigned = true, bool isBigEndian = true)
        {
            if (_obj == null) {
                if (_buffer.Length == 0)
                    return BigInteger.Zero;

                if (_buffer.IsSingleSegment) {
                    return new BigInteger(_buffer.FirstSpan, isUnsigned, isBigEndian);
                } else {
                    //TODO: more efficient thing can probably be done here
                    return new BigInteger(_buffer.ToArray().AsSpan(), isUnsigned, isBigEndian);
                }
            } else {
                if (_obj is string str) {
                    throw new InvalidOperationException("The buffer represents a string and cannot be converted to a big integer");
                } else if (_obj is BigInteger bigInt) {
                    return bigInt;
                } else {
                    throw new NotImplementedException();
                }
            }
        }

        /// <summary>
        /// Try and write bytes to the provided buffer.
        /// </summary>
        /// <param name="buffer">The buffer.</param>
        /// <param name="bytesWritten">The output of bytes written.</param>
        /// <returns>If any of the buffer was copied.</returns>
        public bool TryCopyTo(Span<byte> buffer, out int bytesWritten)
        {
            if (_obj == null) {
                if (buffer.Length < _buffer.Length) {
                    bytesWritten = 0;
                    return false;
                }

                _buffer.CopyTo(buffer);

                bytesWritten = (int)_buffer.Length;
                return true;
            } else {
                throw new InvalidOperationException("The buffer contains an object and cannot be written out");
            }
        }

        /// <summary>
        /// Creates a new message buffer from the memory.
        /// </summary>
        /// <param name="buffer">The buffer.</param>
        public MessageBuffer(ReadOnlySequence<byte> buffer)
        {
            _buffer = buffer;
            _obj = default;
        }

        /// <summary>
        /// Creates a new message buffer from the memory.
        /// </summary>
        /// <param name="buffer">The buffer.</param>
        public MessageBuffer(ReadOnlyMemory<byte> buffer)
        {
            _buffer = new ReadOnlySequence<byte>(buffer);
            _obj = default;
        }

        /// <summary>
        /// Creates a new message buffer from the string.
        /// </summary>
        /// <param name="str">The string.</param>
        public MessageBuffer(string str)
        {
            _buffer = new ReadOnlySequence<byte>();
            _obj = str;
        }

        /// <summary>
        /// Creates a new message buffer from the string.
        /// </summary>
        /// <param name="bigInteger">The big integer.</param>
        public MessageBuffer(BigInteger bigInteger)
        {
            _buffer = new ReadOnlySequence<byte>();
            _obj = bigInteger;
        }
    }
}
