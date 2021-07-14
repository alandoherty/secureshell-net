using SecureShell.Transport;
using SecureShell.Transport.Protocol;
using System;
using System.Buffers;
using System.Buffers.Binary;
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

        private ExchangeContext _ctx;

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

        private byte[] GetIdentification(in SshIdentification identification)
        {
            using (MemoryStream ms = new MemoryStream()) {
                ms.Write(Encoding.ASCII.GetBytes("SSH-"));
                ms.Write(Encoding.ASCII.GetBytes(identification.ProtocolVersion));
                ms.Write(Encoding.ASCII.GetBytes("-"));
                ms.Write(Encoding.ASCII.GetBytes(identification.SoftwareVersion));

                if (!string.IsNullOrEmpty(identification.Comments)) {
                    ms.Write(Encoding.ASCII.GetBytes(" "));
                    ms.Write(Encoding.ASCII.GetBytes(identification.Comments));
                }

                return ms.ToArray();
            }
        }

        private void AppendHashString(IncrementalHash hash, ReadOnlySpan<byte> bytes)
        {
            Span<byte> lengthBytes = stackalloc byte[4];
            BinaryPrimitives.TryWriteInt32BigEndian(lengthBytes, bytes.Length);
            hash.AppendData(lengthBytes);
            hash.AppendData(bytes);
        }

        private byte[] CalculateHash()
        {
            using (IncrementalHash incrementalHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA1)) {
                AppendHashString(incrementalHash, GetIdentification(_ctx.ClientIdentification));
                AppendHashString(incrementalHash, GetIdentification(_ctx.ServerIdentification));
                AppendHashString(incrementalHash, _ctx.ClientInitPayload.Span);
                AppendHashString(incrementalHash, _ctx.ServerInitPayload.Span);
                AppendHashString(incrementalHash, _ctx.Peer._hostKey.ToByteArray());
                AppendHashString(incrementalHash, _clientExchange.ToByteArray(true, true));
                AppendHashString(incrementalHash, _serverExchange.ToByteArray(true, true));
                AppendHashString(incrementalHash, _sharedSecret.ToByteArray(true, true));
                return incrementalHash.GetHashAndReset();
            }
        }

        private BigInteger RandomBigInteger(int bits)
        {
            Span<byte> bytes = stackalloc byte[bits / 8 + (((bits % 8) > 0) ? 1 : 0)];
            RandomNumberGenerator.Fill(bytes);
            bytes[bytes.Length - 1] = (byte)(bytes[bytes.Length - 1] & 0x7F);
            return new BigInteger(bytes);
        }

        /// <inheritdoc/>
        protected internal override async ValueTask ExchangeAsync(Peer peer, ExchangeContext ctx, CancellationToken cancellationToken = default)
        {
            _ctx = ctx;

            // if client we need to send a request
            //TODO: this
            //TODO: private exponents should be twice key material not always 1024 bits

            if (peer.Mode == PeerMode.Client) {
                do {
                    _clientExponent = RandomBigInteger(1024);
                    _clientExchange = BigInteger.ModPow(new BigInteger(2), _clientExponent, Prime);
                } while (_clientExchange < 1 || _clientExchange > (Prime - 1));

                await peer.WritePacketAsync(new InitMessage() {
                    Exchange = new MessageBuffer<BigInteger>(_clientExchange)
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
                        throw new InvalidDataException("The initialization message is invalid");
                    }

                    int bits = initMsg.Exchange.GetByteCount() * 8;

                    if (bits < 2048)
                        throw new InvalidDataException("The client exchange value is of invalid complexity");

                    initMsg.Exchange.Get(out _clientExchange, BufferConverter.BigInteger);
                }

                // calculate shared secret (secret = clientExchange ^ serverExponent mod prime)
                _sharedSecret = BigInteger.ModPow(_clientExchange, _serverExponent, Prime);

                // send reply
                ReplyMessage replyMsg = default;
                replyMsg.HostKeyCertificates = new MessageBuffer<ReadOnlyMemory<byte>>(peer._hostKey.ToByteArray().AsMemory());
                replyMsg.Signature = new MessageBuffer<ReadOnlyMemory<byte>>(peer._hostKey.Sign(CalculateHash(), HashAlgorithmName.SHA1));
                replyMsg.F = new MessageBuffer<BigInteger>(_serverExchange);

                await peer.WritePacketAsync(replyMsg, cancellationToken);
            } else if ((byte)num == SSH_MSG_KEXDH_REPLY) {
                using (packet) {
                    if (!packet.TryDecode<ReplyMessage, ReplyMessage.Decoder>(out ReplyMessage replyMsg)) {
                        throw new InvalidDataException("The reply message is invalid");
                    }

                    replyMsg.F.Get(out _serverExchange, BufferConverter.BigInteger);
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
            public MessageBuffer<ReadOnlyMemory<byte>> HostKeyCertificates;
            public MessageBuffer<BigInteger> F;
            public MessageBuffer<ReadOnlyMemory<byte>> Signature;

            public struct Encoder : IMessageEncoder<ReplyMessage>
            {
                public bool Encode(in ReplyMessage message, IBufferWriter<byte> writer)
                {
                    int byteCount = (int)message.GetByteCount();
                    Span<byte> bytes = writer.GetSpan(byteCount);
                    int offset = 0;

                    bytes[offset] = SSH_MSG_KEXDH_REPLY; 
                    offset++;

                    int hostKeyCertificatesLength = message.HostKeyCertificates.GetByteCount(BufferConverter.ReadOnlyMemory);
                    int fLength = message.F.GetByteCount(BufferConverter.BigInteger);
                    int signatureLength = message.Signature.GetByteCount(BufferConverter.ReadOnlyMemory);

                    // host key certificates
                    BinaryPrimitives.TryWriteInt32BigEndian(bytes.Slice(offset, 4), hostKeyCertificatesLength);
                    offset += 4;
                    message.HostKeyCertificates.TryWriteBytes(bytes.Slice(offset), BufferConverter.ReadOnlyMemory, out int bytesWritten);
                    offset += bytesWritten;

                    // F
                    BinaryPrimitives.TryWriteInt32BigEndian(bytes.Slice(offset, 4), fLength);
                    offset += 4;
                    message.F.TryWriteBytes(bytes.Slice(offset, fLength), BufferConverter.BigInteger, out bytesWritten);
                    offset += bytesWritten;

                    // signature
                    BinaryPrimitives.TryWriteInt32BigEndian(bytes.Slice(offset, 4), signatureLength);
                    offset += 4;
                    message.Signature.TryWriteBytes(bytes.Slice(offset, signatureLength), BufferConverter.ReadOnlyMemory, out int _);

                    writer.Advance(byteCount);

                    return true;
                }

                public void Reset() { }
            }

            public struct Decoder : IMessageDecoder<ReplyMessage>
            {
                /// <inheritdoc/>
                public OperationStatus Decode(ref ReplyMessage message, ref MessageReader reader)
                {
                    OperationStatus status;

                    //TODO: more checks for validity
                    reader.Advance(1);

                    if ((status = reader.TryReadBuffer(out message.HostKeyCertificates)) != OperationStatus.Done) {
                        return status;
                    }

                    if ((status = reader.TryReadBuffer(out message.F)) != OperationStatus.Done) {
                        return status;
                    }

                    if ((status = reader.TryReadBuffer(out message.Signature)) != OperationStatus.Done) {
                        return status;
                    }

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
                + 4U + (uint)HostKeyCertificates.GetByteCount(BufferConverter.ReadOnlyMemory)
                + 4U + (uint)F.GetByteCount(BufferConverter.BigInteger)
                + 4U + (uint)Signature.GetByteCount(BufferConverter.ReadOnlyMemory);
        }
        
        struct InitMessage : IPacketMessage<InitMessage>
        {
            public MessageBuffer<BigInteger> Exchange;

            public struct Encoder : IMessageEncoder<InitMessage>
            {
                public bool Encode(in InitMessage message, IBufferWriter<byte> writer)
                {
                    int messageByteCount = (int)message.GetByteCount();
                    int exchangeByteCount = message.Exchange.GetByteCount(BufferConverter.BigInteger);
                    Span<byte> dataBytes = writer.GetSpan(messageByteCount);

                    dataBytes[0] = SSH_MSG_KEXDH_INIT;

                    // write exchange
                    BinaryPrimitives.TryWriteInt32BigEndian(dataBytes.Slice(1, 4), exchangeByteCount);
                    message.Exchange.TryWriteBytes(dataBytes.Slice(5, exchangeByteCount), BufferConverter.BigInteger, out int _);
                    writer.Advance(messageByteCount);

                    return true;
                }

                public void Reset() { }
            }

            public struct Decoder : IMessageDecoder<InitMessage>
            {
                /// <inheritdoc/>
                public OperationStatus Decode(ref InitMessage message, ref MessageReader reader)
                {
                    reader.Advance(1);

                    OperationStatus status;
                    if ((status = reader.TryReadBuffer(out message.Exchange)) != OperationStatus.Done) {
                        return status;
                    }

                    return OperationStatus.Done;
                }

                /// <inheritdoc/>
                public void Reset() { }
            }

            /// <inheritdoc/>
            public IMessageDecoder<InitMessage> CreateDecoder() => new Decoder();

            /// <inheritdoc/>
            public IMessageEncoder<InitMessage> CreateEncoder() => new Encoder();

            /// <inheritdoc/>
            public uint GetByteCount() => 1U // message number
                + (uint)(4 + Exchange.GetByteCount(BufferConverter.BigInteger));
        }
        #endregion
    }
}
