using SecureShell.Transport;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SecureShell.Security.KeyExchange
{
    /// <summary>
    /// Provides the `diffie-hellman-group14-sha1` key exchange method.
    /// </summary>
    class DiffieHellmanGroupExchangeAlgorithm : ExchangeAlgorithm
    {
        private const byte SSH_MSG_KEXDH_INIT = 30;
        private const byte SSH_MSG_KEXDH_REPLY = 31;

        /// <inheritdoc/>
        public override string Name => "diffie-hellman-group14-sha1";

        /// <inheritdoc/>
        public override ExchangeAlgorithm Reset()
        {
            return new DiffieHellmanExchangeAlgorithm();
        }

        /// <summary>
        /// The 2048-bit shared prime for Group 14 (big endian).
        /// </summary>
        private BigInteger Prime = new BigInteger(new byte[] {
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x68, 0xaa, 0xac, 0x8a,
                0x5a, 0x8e, 0x72, 0x15, 0x10, 0x05, 0xfa, 0x98, 0x18, 0x26, 0xd2, 0x15,
                0xe5, 0x6a, 0x95, 0xea, 0x7c, 0x49, 0x95, 0x39, 0x18, 0x17, 0x58, 0x95,
                0xf6, 0xcb, 0x2b, 0xde, 0xc9, 0x52, 0x4c, 0x6f, 0xf0, 0x5d, 0xc5, 0xb5,
                0x8f, 0xa2, 0x07, 0xec, 0xa2, 0x83, 0x27, 0x9b, 0x03, 0x86, 0x0e, 0x18,
                0x2c, 0x77, 0x9e, 0xe3, 0x3b, 0xce, 0x36, 0x2e, 0x46, 0x5e, 0x90, 0x32,
                0x7c, 0x21, 0x18, 0xca, 0x08, 0x6c, 0x74, 0xf1, 0x04, 0x98, 0xbc, 0x4a,
                0x4e, 0x35, 0x0c, 0x67, 0x6d, 0x96, 0x96, 0x70, 0x07, 0x29, 0xd5, 0x9e,
                0xbb, 0x52, 0x85, 0x20, 0x56, 0xf3, 0x62, 0x1c, 0x96, 0xad, 0xa3, 0xdc,
                0x23, 0x5d, 0x65, 0x83, 0x5f, 0xcf, 0x24, 0xfd, 0xa8, 0x3f, 0x16, 0x69,
                0x9a, 0xd3, 0x55, 0x1c, 0x36, 0x48, 0xda, 0x98, 0x05, 0xbf, 0x63, 0xa1,
                0xb8, 0x7c, 0x00, 0xc2, 0x3d, 0x5b, 0xe4, 0xec, 0x51, 0x66, 0x28, 0x49,
                0xe6, 0x1f, 0x4b, 0x7c, 0x11, 0x24, 0x9f, 0xae, 0xa5, 0x9f, 0x89, 0x5a,
                0xfb, 0x6b, 0x38, 0xee, 0xed, 0xb7, 0x06, 0xf4, 0xb6, 0x5c, 0xff, 0x0b,
                0x6b, 0xed, 0x37, 0xa6, 0xe9, 0x42, 0x4c, 0xf4, 0xc6, 0x7e, 0x5e, 0x62,
                0x76, 0xb5, 0x85, 0xe4, 0x45, 0xc2, 0x51, 0x6d, 0x6d, 0x35, 0xe1, 0x4f,
                0x37, 0x14, 0x5f, 0xf2, 0x6d, 0x0a, 0x2b, 0x30, 0x1b, 0x43, 0x3a, 0xcd,
                0xb3, 0x19, 0x95, 0xef, 0xdd, 0x04, 0x34, 0x8e, 0x79, 0x08, 0x4a, 0x51,
                0x22, 0x9b, 0x13, 0x3b, 0xa6, 0xbe, 0x0b, 0x02, 0x74, 0xcc, 0x67, 0x8a,
                0x08, 0x4e, 0x02, 0x29, 0xd1, 0x1c, 0xdc, 0x80, 0x8b, 0x62, 0xc6, 0xc4,
                0x34, 0xc2, 0x68, 0x21, 0xa2, 0xda, 0x0f, 0xc9, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0x00
            }.AsSpan());

        #region Exchange

        private BigInteger _clientExponent;
        private BigInteger _clientExchange;
        private BigInteger _serverExchange;
        private BigInteger _serverExponent;
        private BigInteger _sharedSecret;

        private BigInteger RandomBigInteger(int bits)
        {
            Span<byte> bytes = stackalloc byte[bits / 8 + (((bits % 8) > 0) ? 1 : 0)];
            RandomNumberGenerator.Fill(bytes);
            bytes[bytes.Length - 1] = (byte)(bytes[bytes.Length - 1] & 0x7F);
            return new BigInteger(bytes, true);
        }

        /// <inheritdoc/>
        protected internal override async ValueTask ExchangeAsync(Peer peer, CancellationToken cancellationToken = default)
        {
            // if client we need to send a request
            //TODO: this
            //TODO: private exponents should be twice key material not always 1024 bits

            if (peer.Mode == PeerMode.Client) {
                do {
                    _clientExponent = RandomBigInteger(1024);
                    _clientExchange = BigInteger.ModPow(new BigInteger(2), _clientExponent, Prime);
                } while (_clientExchange < 1 || _clientExchange > (Prime - 1));

                await peer.WritePacketAsync(new InitMessage() {
                    Exchange = _clientExchange
                }, cancellationToken);
            } else if (peer.Mode == PeerMode.Server) {
                do {
                    _serverExponent = RandomBigInteger(1024);
                    _serverExchange = BigInteger.ModPow(new BigInteger(2), _serverExponent, Prime);
                } while (_serverExchange < 1 || _serverExchange > (Prime - 1));
            } else {
                throw new NotImplementedException();
            }
        }

        /// <inheritdoc/>
        protected internal override async ValueTask<bool> ProcessExchangeAsync(Peer peer, IncomingPacket packet, CancellationToken cancellationToken)
        {
            packet.TryGetMessageNumber(out MessageNumber num);

            if ((byte)num == SSH_MSG_KEXDH_INIT) {
                using (packet) {
                    if (!packet.TryDecode<InitMessage, InitMessage.Decoder>(out InitMessage initMsg)) {
                        throw new InvalidDataException("The initialisation message is invalid");
                    }

                    int bits = initMsg.Exchange.GetByteCount() * 8;

                    if (bits < 2048)
                        throw new InvalidDataException("The client exchange value is of invalid complexity");

                    _clientExchange = initMsg.Exchange;
                }

                // calculate shared secret (secret = clientExchange ^ serverExponent mod prime)
                _sharedSecret = BigInteger.ModPow(_clientExchange, _serverExponent, Prime);

                // send reply
                ReplyMessage replyMsg = default;
                replyMsg.HostKeyCertificates = peer._hostKey.ToByteArray();
                replyMsg.Signature = peer._hostKey.Sign(Span<byte>.Empty, HashAlgorithmName.SHA1);
                replyMsg.F = _serverExchange;

                await peer.WritePacketAsync(replyMsg, cancellationToken);
            } else if ((byte)num == SSH_MSG_KEXDH_REPLY) {
                using (packet) {
                    if (!packet.TryDecode<ReplyMessage, ReplyMessage.Decoder>(out ReplyMessage replyMsg)) {
                        throw new InvalidDataException("The reply message is invalid");
                    }

                    _serverExchange = replyMsg.F;
                    //TODO: this
                }

                // calculate shared secret (secret = serverExchange ^ clientExponent mod prime)
                _sharedSecret = BigInteger.ModPow(_serverExchange, _clientExponent, Prime);
            } else {
                return false;
            }

            return false;
        }
        #endregion

        #region Messages
        struct ReplyMessage : IPacketMessage<ReplyMessage>
        {
            public ReadOnlyMemory<byte> HostKeyCertificates;
            public BigInteger F;
            public ReadOnlyMemory<byte> Signature;

            public struct Encoder : IMessageEncoder<ReplyMessage>
            {
                public bool Encode(in ReplyMessage message, IBufferWriter<byte> writer)
                {
                    int byteCount = (int)message.GetByteCount();
                    Span<byte> bytes = writer.GetSpan(byteCount);
                    int offset = 0;
                    
                    bytes[offset] = SSH_MSG_KEXDH_REPLY; 
                    offset++;

                    // host key certificates
                    BitConverter.TryWriteBytes(bytes.Slice(offset, 4), (uint)message.HostKeyCertificates.Length);
                    bytes.Slice(offset, 4).Reverse();
                    offset += 4;

                    message.HostKeyCertificates.Span.CopyTo(bytes.Slice(offset, message.HostKeyCertificates.Length));
                    offset += message.HostKeyCertificates.Length;

                    // F
                    BitConverter.TryWriteBytes(bytes.Slice(offset, 4), (uint)message.F.GetByteCount());
                    bytes.Slice(offset, 4).Reverse();
                    offset += 4;

                    message.F.TryWriteBytes(bytes.Slice(offset, message.F.GetByteCount()), out _, false, true);
                    offset += message.F.GetByteCount();

                    // signature
                    BitConverter.TryWriteBytes(bytes.Slice(offset, 4), (uint)message.Signature.Length);
                    bytes.Slice(offset, 4).Reverse();
                    offset += 4;

                    message.Signature.Span.CopyTo(bytes.Slice(offset, message.Signature.Length));

                    writer.Advance(byteCount);

                    return true;
                }

                public void Reset() { }
            }

            public struct Decoder : IMessageDecoder<ReplyMessage>
            {
                /// <inheritdoc/>
                public OperationStatus Decode(ref ReplyMessage message, ref SequenceReader<byte> reader)
                {
                    //TODO: more checks for validity
                    reader.Advance(1);
                    int offset = 1;

                    reader.TryReadBigEndian(out int hostKeyLen);
                    offset += 4;
                    message.HostKeyCertificates = reader.Sequence.First.Slice(offset, hostKeyLen);
                    reader.Advance(hostKeyLen);
                    offset += hostKeyLen;

                    reader.TryReadBigEndian(out int fLen);
                    offset += 4;
                    message.F = new BigInteger(reader.Sequence.FirstSpan.Slice(offset, fLen), false, true);
                    reader.Advance(fLen);
                    offset += fLen;

                    reader.TryReadBigEndian(out int signatureLen);
                    offset += 4;
                    message.Signature = reader.Sequence.First.Slice(offset, signatureLen);
                    reader.Advance(signatureLen);
                    offset += signatureLen;

                    return OperationStatus.Done;
                }

                /// <inheritdoc/>
                public void Reset() { }
            }

            /// <inheritdoc/>
            public IMessageDecoder<ReplyMessage> CreateDecoder() => new Decoder();

            /// <inheritdoc/>
            public IMessageEncoder<ReplyMessage> CreateEncoder() => new Encoder();

            /// <inheritdoc/>
            public uint GetByteCount() => 1U
                + 4U + (uint)HostKeyCertificates.Length
                + 4U + (uint)F.GetByteCount()
                + 4U + (uint)Signature.Length;
        }
        
        struct InitMessage : IPacketMessage<InitMessage>
        {
            public BigInteger Exchange;

            public struct Encoder : IMessageEncoder<InitMessage>
            {
                public bool Encode(in InitMessage message, IBufferWriter<byte> writer)
                {
                    int exchangeByteCount = message.Exchange.GetByteCount();
                    Span<byte> dataBytes = writer.GetSpan(5 + exchangeByteCount);

                    dataBytes[0] = SSH_MSG_KEXDH_INIT;

                    // write exchange
                    BitConverter.TryWriteBytes(dataBytes.Slice(1, 4), exchangeByteCount);
                    dataBytes.Slice(1, 4).Reverse();
                    message.Exchange.TryWriteBytes(dataBytes.Slice(5, exchangeByteCount), out _, false, true);
                    writer.Advance(5 + exchangeByteCount);

                    return true;
                }

                public void Reset() { }
            }

            public struct Decoder : IMessageDecoder<InitMessage>
            {
                private int _exponentByteCount;
                private bool _exponent;

                /// <inheritdoc/>
                public OperationStatus Decode(ref InitMessage message, ref SequenceReader<byte> reader)
                {
                    reader.Advance(1);

                    //TODO: deny too big exponent
                    if (!_exponent) {
                        if (reader.Remaining < 4)
                            return OperationStatus.NeedMoreData;

                        reader.TryReadBigEndian(out _exponentByteCount);
                        _exponent = true;
                    }

                    if (reader.Remaining < _exponentByteCount)
                        return OperationStatus.NeedMoreData;

                    if (reader.UnreadSpan.Length >= _exponentByteCount) {
                        message.Exchange = new BigInteger(reader.UnreadSpan.Slice(0, _exponentByteCount), false, true);
                    } else {
                        byte[] exponentBytes = new byte[_exponentByteCount];
                        reader.TryCopyTo(exponentBytes.AsSpan());
                        message.Exchange = new BigInteger(exponentBytes, false, true);
                    }

                    return OperationStatus.Done;
                }

                /// <inheritdoc/>
                public void Reset() {
                    _exponent = false;
                }
            }

            /// <inheritdoc/>
            public IMessageDecoder<InitMessage> CreateDecoder() => new Decoder();

            /// <inheritdoc/>
            public IMessageEncoder<InitMessage> CreateEncoder() => new Encoder();

            /// <inheritdoc/>
            public uint GetByteCount() => 1U // message number
                + (uint)(4 + Exchange.GetByteCount());
        }
        #endregion
    }
}
