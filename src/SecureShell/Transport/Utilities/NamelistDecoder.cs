using System;
using System.Buffers;
using System.Collections.Generic;
using System.Text;

namespace SecureShell.Transport.Utilities
{
    /// <summary>
    /// A helper decoder for namelists.
    /// </summary>
    public struct NamelistDecoder
    {
        private int? _length;
        private int _processedLength;

        /// <summary>
        /// Decode a namelist from the provided sequence reader. 
        /// </summary>
        /// <param name="names"></param>
        /// <param name="reader"></param>
        /// <returns></returns>
        public OperationStatus Decode(List<string> names, ref SequenceReader<byte> reader)
        {
            // we need to read the length first
            if (_length == null) {
                if (reader.Remaining < 4)
                    return OperationStatus.NeedMoreData;

                reader.TryReadBigEndian(out int nameListLength);
                _length = nameListLength;
                _processedLength = 0;
            }
            
            // create a new sequence reader from the existing sequence this allows us to limit the sequence if we need to, and also gives us
            // full control over advancing the original sequence reader
            SequenceReader<byte> copyReader;
            int remainingLength = (int)(_length.Value - _processedLength);

            if (remainingLength == 0) {
                return OperationStatus.Done;
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
                        return OperationStatus.Done;
                    } else {
                        // we limit the strings to 255 bytes maximum for each name, this is important as since we don't buffer
                        // them we take directly from the sequence. this prevents copying but must be careful not to elapse
                        // the buffer of our caller so we must give up eventually after not receiving a comma
                        if (remainingLength > 256)
                            return OperationStatus.InvalidData;

                        return OperationStatus.NeedMoreData;
                    }
                }
            }

            // if we've processed everything we're done
            if (_processedLength == _length)
                return OperationStatus.Done;

            return OperationStatus.NeedMoreData;
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