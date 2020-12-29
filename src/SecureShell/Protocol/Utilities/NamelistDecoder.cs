using System;
using System.Buffers;
using System.Collections.Generic;
using System.Text;

namespace SecureShell.Protocol.Utilities
{
    /// <summary>
    /// A helper decoder for namelists.
    /// </summary>
    public struct NamelistDecoder
    {
        private int? _length;
        private int _processedLength;

        /// <summary>
        /// Gets the length.
        /// </summary>
        public uint? Length => (uint?)_length;

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
            /// The current name is bigger than 255 bytes.
            /// </summary>
            NameTooBig,
            
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
                _length = nameListLength;
                _processedLength = 0;
                
                return DecodeResult.Length;
            }
            
            // create a new sequence reader from the existing sequence this allows us to limit the sequence if we need to, and also gives us
            // full control over advancing the original sequence reader
            SequenceReader<byte> copyReader;
            int remainingLength = (int)(_length.Value - _processedLength);

            if (remainingLength == 0) {
                return DecodeResult.Complete;
            }

            if (reader.Remaining > remainingLength) {
                copyReader = new SequenceReader<byte>(reader.Sequence.Slice(reader.Position, remainingLength));
            } else {
                copyReader = new SequenceReader<byte>(reader.Sequence.Slice(reader.Position));
            }
            
            // keep advancing to a comma until there is nothing left
            //TODO: possibly a more efficient way of building the strings without creating an array
            while (copyReader.Remaining > 0) {
                if (copyReader.TryReadTo(out ReadOnlySequence<byte> nameSequence, (byte) ',')) {
                    reader.Advance(nameSequence.Length + 1);
                  
                    if (nameSequence.IsSingleSegment) {
                        names.Add(Encoding.ASCII.GetString(nameSequence.FirstSpan));
                    } else {
                        names.Add(Encoding.ASCII.GetString(nameSequence.ToArray()));
                    }

                    // advance the amount of the total length that we've processed, we need to include the comma too
                    _processedLength += (int)nameSequence.Length + 1;
                    remainingLength = (int)(_length.Value - _processedLength); 
                } else {
                    if (remainingLength <= copyReader.Remaining) {
                        byte[] remainingNameBytes = new byte[(int)copyReader.Remaining];
                        copyReader.TryCopyTo(remainingNameBytes.AsSpan());
                        reader.Advance(remainingNameBytes.Length);
                        names.Add(Encoding.ASCII.GetString(remainingNameBytes));
                        return DecodeResult.Complete;
                    } else {
                        // we limit the strings to 255 bytes maximum for each name, this is important as since we don't buffer
                        // them we take directly from the sequence. this prevents copying but must be careful not to elapse
                        // the buffer of our caller so we must give up eventually after not receiving a comma
                        if (remainingLength > 256)
                            return DecodeResult.NameTooBig;

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