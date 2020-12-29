using SecureShell.Protocol.Utilities;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SecureShell.Protocol.Messages
{
    public struct KeyInitializationMessage : IPacketMessage<KeyInitializationMessage>
    {
        /// <summary>
        /// The first 8 bytes of the cookie.
        /// </summary>
        public long Cookie1;
        
        /// <summary>
        /// The second 8 bytes of the cookie.
        /// </summary>
        public long Cookie2;

        public List<string> KeyExchangeAlgorithms;

        public List<string> ServerHostKeyAlgorithms;

        public List<string> EncryptionAlgorithmsClientToServer;
        public List<string> EncryptionAlgorithmsServerToClient;
        public List<string> MacAlgorithmsClientToServer;
        public List<string> MacAlgorithmsServerToClient;
        public List<string> CompressionAlgorithmsClientToServer;
        public List<string> CompressionAlgorithmsServerToClient;
        public List<string> LanguagesClientToServer;
        public List<string> LanguagesServerToClient;

        /// <summary>
        /// If the first key exchange packet follows with a guess.
        /// </summary>
        public bool FirstKeyExchangePacketFollows;

        /// <summary>
        /// The reserved value, not currently used and SHOULD (?) be zero.
        /// </summary>
        public uint Reserved;

        /// <summary>
        /// The decoder for the key initialization message.
        /// </summary>
        public struct Decoder : IMessageDecoder<KeyInitializationMessage>
        {
            private State _state;
            private int _nameListIndex;
            private NamelistDecoder _nameListDecoder;
            
            enum State
            {
                Cookie,
                NameList,
                Tail,
                Completed
            }
            
            public bool Decode(ref KeyInitializationMessage message, ref SequenceReader<byte> reader)
            {
                while (true) {
                    if (_state == State.Cookie) {
                        // we need 16 bytes to read the cookie
                        if (reader.Remaining < 16)
                            return true;
                        
                        // extract the cookie
                        if (BitConverter.IsLittleEndian) {
                            reader.TryReadLittleEndian(out message.Cookie1);
                            reader.TryReadLittleEndian(out message.Cookie2);
                        } else {
                            reader.TryReadBigEndian(out message.Cookie1);
                            reader.TryReadBigEndian(out message.Cookie2);
                        }

                        _state = State.NameList;
                    } else if (_state == State.NameList) {
                        // get the name list for the current index
                        List<string> names = null;

                        while (_nameListIndex != 10) {
                            // select the correct namelist, creating it if it does not exist already
                            switch (_nameListIndex) {
                                case 0:
                                    names = message.KeyExchangeAlgorithms ??= new List<string>();
                                    break;
                                case 1:
                                    names = message.ServerHostKeyAlgorithms ??= new List<string>();
                                    break;
                                case 2:
                                    names = message.EncryptionAlgorithmsClientToServer ??= new List<string>();
                                    break;
                                case 3:
                                    names = message.EncryptionAlgorithmsServerToClient ??= new List<string>();
                                    break;
                                case 4:
                                    names = message.MacAlgorithmsClientToServer ??= new List<string>();
                                    break;
                                case 5:
                                    names = message.MacAlgorithmsServerToClient ??= new List<string>();
                                    break;
                                case 6:
                                    names = message.CompressionAlgorithmsClientToServer ??= new List<string>();
                                    break;
                                case 7:
                                    names = message.CompressionAlgorithmsServerToClient ??= new List<string>();
                                    break;
                                case 8:
                                    names = message.LanguagesClientToServer ??= new List<string>();
                                    break;
                                case 9:
                                    names = message.LanguagesServerToClient ??= new List<string>();
                                    break;
                            }

                            // decode the namelist as much as possible
                            var decodeResult = _nameListDecoder.Decode(names, ref reader);

                            if (decodeResult == NamelistDecoder.DecodeResult.NeedsData) {
                                return true;
                            } else if (decodeResult == NamelistDecoder.DecodeResult.Length) {
                                continue;
                            }

                            _nameListIndex++;
                            _nameListDecoder.Reset();
                        }

                        // once we've got all 10 namelists we're done
                        _state = State.Tail;
                    } else if (_state == State.Tail) {
                        // we need 16 bytes to read the cookie
                        if (reader.Remaining < 5)
                            return true;

                        reader.TryRead(out byte firstKexFollows);
                        message.FirstKeyExchangePacketFollows = firstKexFollows == 1;
                        reader.TryReadBigEndian(out int reserved);
                        message.Reserved = (uint)reserved;
                        _state = State.Completed;
                    } else {
                        return false;
                    }
                }
            }

            /// <inheritdoc/>
            public void Reset()
            {
                _state = default;
                _nameListDecoder = default;
                _nameListIndex = default;
            }
        }

        /// <summary>
        /// The encoder for the key initialization message.
        /// </summary>
        public struct Encoder : IMessageEncoder<KeyInitializationMessage>
        {
            public bool Encode(in KeyInitializationMessage message, IBufferWriter<byte> writer)
            {
                throw new NotImplementedException();
            }

            public void Reset()
            {
               
                throw new NotImplementedException();
            }
        }

        /// <inheritdoc/>
        public int GetByteCount()
        {
            static int GetNamesByteCount(List<string> names)
            {
                return (names.Count <= 1 ? 0 : names.Count - 1) // commas
                    + names.Sum(s => Encoding.ASCII.GetByteCount(s)); // contents
            }

            return 16 // cookie
                + 40 // namelist lengths
                + GetNamesByteCount(KeyExchangeAlgorithms)
                + GetNamesByteCount(ServerHostKeyAlgorithms)
                + GetNamesByteCount(EncryptionAlgorithmsClientToServer)
                + GetNamesByteCount(EncryptionAlgorithmsServerToClient)
                + GetNamesByteCount(MacAlgorithmsClientToServer)
                + GetNamesByteCount(MacAlgorithmsServerToClient)
                + GetNamesByteCount(CompressionAlgorithmsClientToServer)
                + GetNamesByteCount(CompressionAlgorithmsServerToClient)
                + GetNamesByteCount(LanguagesClientToServer)
                + GetNamesByteCount(LanguagesServerToClient)
                + 5; // tail boolean and reserved
        }

        /// <inheritdoc/>
        public IMessageDecoder<KeyInitializationMessage> CreateDecoder()
        {
            return new Decoder();
        }
        
        /// <inheritdoc/>
        public IMessageEncoder<KeyInitializationMessage> CreateEncoder()
        {
            return new Encoder();
        }
    }
}
