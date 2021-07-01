using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Numerics;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SecureShell.Transport.KeyExchange
{
    class DiffieHellmanGroupExchangeAlgorithm : ExchangeAlgorithm
    {
        private const byte SSH_MSG_KEXDH_INIT = 30;
        private const byte SSH_MSG_KEXDH_REPLY = 31;

        #region Exchange
        private BigInteger _exchange;

        /// <inheritdoc/>
        public override ValueTask ExchangeAsync(CancellationToken cancellationToken = default)
        {
            // if client we need to send a request
            //TODO: this
            return default;
        }

        /// <inheritdoc/>
        public override async ValueTask<bool> ProcessExchangeAsync(IncomingPacket packet, CancellationToken cancellationToken)
        {
            packet.TryGetMessageNumber(out MessageNumber num);

            if ((byte)num == SSH_MSG_KEXDH_INIT) {
                if (!packet.TryDecode<InitMessage, InitMessage.Decoder>(out InitMessage initMsg)) {
                    throw new InvalidDataException("The initialisation message is invalid");
                }

                _exchange = initMsg.Exchange;
            } else if ((byte)num == SSH_MSG_KEXDH_REPLY) {
                //TODO: no support for client peers yet
                throw new NotImplementedException();
            } else {
                return false;
            }

            return false;
        }
        #endregion

        #region Messages
        struct ReplyMessage : IPacketMessage<ReplyMessage>
        {
            public string HostKeyCertificates;
            public BigInteger F;
            public string Signature;

            public struct Encoder : IMessageEncoder<ReplyMessage>
            {
                public bool Encode(in ReplyMessage message, IBufferWriter<byte> writer)
                {
                    return true;
                }

                public void Reset() { }
            }

            public struct Decoder : IMessageDecoder<ReplyMessage>
            {
                /// <inheritdoc/>
                public OperationStatus Decode(ref ReplyMessage message, ref SequenceReader<byte> reader)
                {
                    throw new NotImplementedException();
                }

                /// <inheritdoc/>
                public void Reset() { }
            }

            /// <inheritdoc/>
            public IMessageDecoder<ReplyMessage> CreateDecoder() => new Decoder();

            /// <inheritdoc/>
            public IMessageEncoder<ReplyMessage> CreateEncoder() => new Encoder();

            /// <inheritdoc/>
            public uint GetByteCount() => throw new NotImplementedException();
        }
        
        struct InitMessage : IPacketMessage<InitMessage>
        {
            public BigInteger Exchange;

            public struct Encoder : IMessageEncoder<InitMessage>
            {
                public bool Encode(in InitMessage message, IBufferWriter<byte> writer)
                {
                    int exchangeByteCount = message.Exchange.GetByteCount();

                    Span<byte> dataBytes = writer.GetSpan(4 + exchangeByteCount);

                    // write exchange
                    BitConverter.TryWriteBytes(dataBytes.Slice(0, 4), exchangeByteCount);
                    dataBytes.Slice(0, 4).Reverse();
                    message.Exchange.TryWriteBytes(dataBytes.Slice(4, exchangeByteCount), out _);
                    dataBytes.Slice(4, exchangeByteCount).Reverse();

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
            public uint GetByteCount() => (uint)(4 + Exchange.GetByteCount());
        }
        #endregion
    }
}
