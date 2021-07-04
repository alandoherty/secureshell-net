using SecureShell.Transport;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Numerics;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SecureShell.Security.KeyExchange
{
    class DiffieHellmanExchangeAlgorithm : ExchangeAlgorithm
    {
        private const byte SSH_MSG_KEX_DH_GEX_REQUEST_OLD = 30;
        private const byte SSH_MSG_KEX_DH_GEX_REQUEST = 34;
        private const byte SSH_MSG_KEX_DH_GEX_GROUP = 31;

        /// <inheritdoc/>
        public override string Name => throw new NotImplementedException();

        /// <inheritdoc/>
        public override ExchangeAlgorithm Reset()
        {
            return new DiffieHellmanExchangeAlgorithm();
        }

        #region Exchange
        private int _groupSize;

        /// <inheritdoc/>
        protected internal override ValueTask ExchangeAsync(Peer peer, CancellationToken cancellationToken = default)
        {
            // reset
            _groupSize = default;

            // if client we need to send a request
            //TODO: this
            return default;
        }

        /// <inheritdoc/>
        protected internal override async ValueTask<bool> ProcessExchangeAsync(Peer peer, IncomingPacket packet, CancellationToken cancellationToken)
        {
            packet.TryGetMessageNumber(out MessageNumber num);

            if ((byte)num == SSH_MSG_KEX_DH_GEX_REQUEST_OLD) {
                //TODO: implement the older message
                throw new NotImplementedException();

            } else if ((byte)num == SSH_MSG_KEX_DH_GEX_REQUEST) {
                /*
                // read request
                RequestExchangeMessage req = await peer.ReadMessageAsync<RequestExchangeMessage, RequestExchangeMessage.Decoder>(default, cancellationToken);

                _groupSize = (int)req.N;

                // respond
                GroupExchangeMessage group = default;

                await peer.WritePacketAsync<GroupExchangeMessage, GroupExchangeMessage.Encoder>((MessageNumber)SSH_MSG_KEX_DH_GEX_GROUP, group, default, cancellationToken);
                */
            }  else if ((byte)num == SSH_MSG_KEX_DH_GEX_GROUP) {
                //TODO: no support for client peers yet
                throw new NotImplementedException();
            }

            return false;
        }
        #endregion

        #region Messages
        struct RequestExchangeMessage : IPacketMessage<RequestExchangeMessage>
        {
            public uint Minimum;
            public uint N;
            public uint Maximum;

            //TODO: not tested
            public struct Encoder : IMessageEncoder<RequestExchangeMessage>
            {
                /// <inheritdoc/>
                public bool Encode(in RequestExchangeMessage message, IBufferWriter<byte> writer)
                {
                    Span<byte> bytes = writer.GetSpan(12);

                    BitConverter.TryWriteBytes(bytes.Slice(0, 4), message.Minimum);
                    bytes.Slice(0, 4).Reverse();

                    BitConverter.TryWriteBytes(bytes.Slice(4, 4), message.N);
                    bytes.Slice(4, 4).Reverse();

                    BitConverter.TryWriteBytes(bytes.Slice(8, 4), message.Maximum);
                    bytes.Slice(8, 4).Reverse();

                    writer.Advance(12);
                    return true;
                }

                /// <inheritdoc/>
                public void Reset() { }
            }

            public struct Decoder : IMessageDecoder<RequestExchangeMessage>
            {
                /// <inheritdoc/>
                public OperationStatus Decode(ref RequestExchangeMessage message, ref SequenceReader<byte> reader)
                {
                    if (reader.Remaining < 12)
                        return OperationStatus.NeedMoreData;

                    int a;

                    reader.TryReadBigEndian(out a);
                    message.Minimum = (uint)a;

                    reader.TryReadBigEndian(out a);
                    message.N = (uint)a;

                    reader.TryReadBigEndian(out a);
                    message.Maximum = (uint)a;

                    return OperationStatus.Done;
                }

                /// <inheritdoc/>
                public void Reset() { }
            }

            /// <inheritdoc/>
            public IMessageDecoder<RequestExchangeMessage> CreateDecoder() => new Decoder();

            /// <inheritdoc/>
            public IMessageEncoder<RequestExchangeMessage> CreateEncoder() => new Encoder();

            /// <inheritdoc/>
            public uint GetByteCount() => 12;
        }

        struct GroupExchangeMessage : IPacketMessage<GroupExchangeMessage>
        {
            public BigInteger Prime;
            public BigInteger Generator;

            public struct Encoder : IMessageEncoder<GroupExchangeMessage>
            {
                public bool Encode(in GroupExchangeMessage message, IBufferWriter<byte> writer)
                {
                    int primeByteCount = message.Prime.GetByteCount();
                    int generatorByteCount = message.Generator.GetByteCount();

                    Span<byte> dataBytes = writer.GetSpan(8 + primeByteCount + generatorByteCount);

                    // write prime
                    BitConverter.TryWriteBytes(dataBytes.Slice(0, 4), primeByteCount);
                    dataBytes.Slice(0, 4).Reverse();
                    message.Prime.TryWriteBytes(dataBytes.Slice(4, primeByteCount), out _);
                    dataBytes.Slice(4, primeByteCount).Reverse();

                    // write generator
                    BitConverter.TryWriteBytes(dataBytes.Slice(4 + primeByteCount, 4), generatorByteCount);
                    dataBytes.Slice(4 + primeByteCount, 4).Reverse();
                    message.Generator.TryWriteBytes(dataBytes.Slice(4 + primeByteCount + 4, generatorByteCount), out _);
                    dataBytes.Slice(4 + primeByteCount + 4, generatorByteCount).Reverse();

                    return true;
                }

                public void Reset() { }
            }

            public struct Decoder : IMessageDecoder<GroupExchangeMessage>
            {
                /// <inheritdoc/>
                public OperationStatus Decode(ref GroupExchangeMessage message, ref SequenceReader<byte> reader)
                {
                    throw new NotImplementedException();
                }

                /// <inheritdoc/>
                public void Reset() { }
            }

            /// <inheritdoc/>
            public IMessageDecoder<GroupExchangeMessage> CreateDecoder() => new Decoder();

            /// <inheritdoc/>
            public IMessageEncoder<GroupExchangeMessage> CreateEncoder() => new Encoder();

            /// <inheritdoc/>
            public uint GetByteCount() => (uint)(8 + Prime.GetByteCount() + Generator.GetByteCount());
        }
        #endregion
    }
}
