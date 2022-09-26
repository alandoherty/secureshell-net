using SecureShell.Transport;
using SecureShell.Transport.Protocol;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using SecureShell.Transport.Utilities;

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
        private BigInteger Prime = BigInteger.Parse(
            "00FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
            NumberStyles.HexNumber);

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
                AppendHashString(incrementalHash, MpInteger.ToByteArray(_clientExchange));
                AppendHashString(incrementalHash, MpInteger.ToByteArray(_serverExchange));
                AppendHashString(incrementalHash, MpInteger.ToByteArray(_sharedSecret));
                return incrementalHash.GetHashAndReset();
            }
        }

        private BigInteger RandomBigInteger(int bits)
        {
            Span<byte> bytes = stackalloc byte[bits / 8];
            RandomNumberGenerator.Fill(bytes);
            return BigInteger.Abs(new BigInteger(bytes));
        }

        /// <inheritdoc/>
        protected internal override async ValueTask StartAsync(Peer peer, ExchangeContext ctx, CancellationToken cancellationToken = default)
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
        protected internal override async ValueTask<ExchangeOutput> ProcessAsync(Peer peer, IncomingPacket packet, CancellationToken cancellationToken = default)
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
                byte[] signatureData = peer._hostKey.Sign(CalculateHash(), HashAlgorithmName.SHA1);

                ReplyMessage replyMsg = default;
                replyMsg.HostKeyCertificates = new MessageBuffer<ReadOnlyMemory<byte>>(peer._hostKey.ToByteArray().AsMemory());
                replyMsg.Signature = new MessageBuffer<ReadOnlyMemory<byte>>(signatureData);
                replyMsg.F = new MessageBuffer<BigInteger>(_serverExchange);

                await peer.WritePacketAsync(replyMsg, cancellationToken);
                
                // Return true now we've completed the exchange
                return new ExchangeOutput(CalculateHash(), CalculateHash(), _sharedSecret, SHA1.Create());
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
                return null;
            }

            return null;
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
                    message.HostKeyCertificates.TryWriteBytes(bytes.Slice(offset, hostKeyCertificatesLength), BufferConverter.ReadOnlyMemory, out int bytesWritten);
                    offset += bytesWritten;

                    // F
                    BinaryPrimitives.TryWriteInt32BigEndian(bytes.Slice(offset, 4), fLength);
                    offset += 4;
                    message.F.TryWriteBytes(bytes.Slice(offset, fLength), BufferConverter.BigInteger, out bytesWritten);
                    offset += bytesWritten;

                    // signature
                    BinaryPrimitives.TryWriteInt32BigEndian(bytes.Slice(offset, 4), signatureLength);
                    offset += 4;
                    message.Signature.TryWriteBytes(bytes.Slice(offset, signatureLength), BufferConverter.ReadOnlyMemory, out bytesWritten);
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
            public readonly IMessageDecoder<ReplyMessage> CreateDecoder() => new Decoder();

            /// <inheritdoc/>
            public readonly IMessageEncoder<ReplyMessage> CreateEncoder() => new Encoder();

            /// <inheritdoc/>
            public readonly uint GetByteCount() => 1U
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
            public readonly IMessageDecoder<InitMessage> CreateDecoder() => new Decoder();

            /// <inheritdoc/>
            public readonly IMessageEncoder<InitMessage> CreateEncoder() => new Encoder();

            /// <inheritdoc/>
            public readonly uint GetByteCount() => 1U // message number
                                                   + (uint)(4 + Exchange.GetByteCount(BufferConverter.BigInteger));
        }
        #endregion
    }
}
