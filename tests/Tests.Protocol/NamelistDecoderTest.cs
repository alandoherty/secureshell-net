using SecureShell.Protocol.Utilities;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace Tests.Protocol
{
    /// <summary>
    /// Represents the namelist decoder.
    /// </summary>
    public class NamelistDecoderTest
    {
        public static IEnumerable<object[]> ValidNamelists = new object[][] {
            new object[] { new string[] { "ssh-potato", "ext-c@notreal.org", "sha256-hmac", "_____", "undermac" } },
            new object[] { new string[] { "ssh-potato" } }
        };

        private byte[] BuildNamelist(string[] names)
        {
            using (MemoryStream ms = new MemoryStream()) {
                BinaryWriter writer = new BinaryWriter(ms);

                // build namelist contents
                string namelist = string.Join(',', names);

                // write length
                Span<byte> lengthBytes = stackalloc byte[4];
                BitConverter.TryWriteBytes(lengthBytes, Encoding.ASCII.GetByteCount(namelist));
                lengthBytes.Reverse();
                writer.Write(lengthBytes);

                // write contents
                writer.Write(Encoding.ASCII.GetBytes(namelist));

                return ms.ToArray();
            }
        }

        /// <summary>
        /// Decodes namelist <see cref="ValidNamelist"/> as a single segment in a sequence.
        /// </summary>
        [Theory]
        [MemberData(nameof(ValidNamelists))]
        public void DecodeValidNamelistSingleSegment(string[] namelist)
        {
            List<string> names = new List<string>();
            NamelistDecoder decoder = new NamelistDecoder();
            ReadOnlySequence<byte> sequence = new ReadOnlySequence<byte>(BuildNamelist(namelist));
            SequenceReader<byte> sequenceReader = new SequenceReader<byte>(sequence);

            if (decoder.Decode(names, ref sequenceReader) != NamelistDecoder.DecodeResult.Length) {
                throw new Exception("The decoder did not return the length");
            }

            if (decoder.Decode(names, ref sequenceReader) != NamelistDecoder.DecodeResult.Complete) {
                throw new Exception("The decoder did not return the length");
            }

            if (!Enumerable.SequenceEqual(names, namelist)) {
                throw new Exception("The decoded names are not equal to the encoded names");
            }
        }
    }
}
