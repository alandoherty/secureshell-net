using System;
using System.Buffers;
using System.Collections.Generic;
using System.Text;

namespace SecureShell.Protocol.Utilities
{
    /// <summary>
    /// A helper decoder for namelists.
    /// </summary>
    internal struct NamelistDecoder
    {
        private uint? _length;
        private uint _processedLength;

        /// <summary>
        /// Gets the length.
        /// </summary>
        public uint? Length => _length;

        /// <summary>
        /// Defines the result of a decode operation.
        /// </summary>
        public enum DecodeResult
        {
            /// <summary>
            /// The length has been decoded.
            /// </summary>
            Length,
            
            /// <summary>
            /// Needs more data to decode.
            /// </summary>
            NeedsData,
            
            /// <summary>
            /// Completes the decoding.
            /// </summary>
            Complete
        }

        /// <summary>
        /// Decode a namelist from the provided sequence reader. 
        /// </summary>
        /// <param name="names"></param>
        /// <param name="reader"></param>
        /// <returns></returns>
        public DecodeResult Decode(List<string> names, ref SequenceReader<byte> reader)
        {
            // we need to read the namelist length first
            if (_length == null) {
                if (reader.Remaining < 4)
                    return DecodeResult.NeedsData;

                reader.TryReadBigEndian(out int nameListLength);
                _length = (uint)nameListLength;
                _processedLength = 0;
                
                return DecodeResult.Length;
            }
            
            // create a new sequence reader limited to only the namelist data if we have more data
            SequenceReader<byte> limitedReader;

            if (reader.Remaining > _length) {
                limitedReader = new SequenceReader<byte>(reader.Sequence.Slice(0, (long)_length.Value - _processedLength));
            } else {
                limitedReader = reader;
            }
            
            // keep advancing to a comma until there is nothing left
            //TODO: possibly a more efficient way of building the strings without creating an array
            while (limitedReader.Remaining > 0) {
                if (reader.TryReadTo(out ReadOnlySequence<byte> nameSequence, (byte) ',')) {
                    names.Add(Encoding.ASCII.GetString(nameSequence.ToArray()));
                } else {
                    if (_processedLength + (uint)reader.Consumed == _length.Value) {
                        byte[] remainingNameBytes = new byte[(int)reader.Remaining];
                        reader.TryCopyTo()
                        names.Add(Encoding.ASCII.GetString(remainingNameBytes));
                        return DecodeResult.Complete
                    } else {
                        _processedLength += (uint)reader.Consumed;
                        return DecodeResult.NeedsData;
                    }
                }
            }

            // if we've processed everything we're done
            if (_processedLength == _length)
                return DecodeResult.Complete;

            return DecodeResult.NeedsData;
        }
        
        /// <summary>
        /// Reset the decoder.
        /// </summary>
        public void Reset()
        {
            _processedLength = default;
            _length = null;
        }
    }
}