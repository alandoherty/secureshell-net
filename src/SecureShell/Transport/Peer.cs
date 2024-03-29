﻿using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipelines;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using SecureShell.Security.Encryption;
using SecureShell.Security.Hosts;
using SecureShell.Security.Integrity;
using SecureShell.Security.KeyExchange;
using SecureShell.Transport;
using SecureShell.Transport.Messages;
using SecureShell.Transport.Protocol;

namespace SecureShell.Transport
{
    /// <summary>
    /// Represents a SSH2 peer and provides functionality to read/write packets. It handles the SSH Transport state, accepting services and processing data but does not deal with user authentication or other services.
    /// </summary>
    public class Peer
    {
        private readonly PeerMode _mode;
        private PeerState _state = PeerState.IdentificationExchange;
        private readonly PipeReader _reader;
        private readonly PipeWriter _writer;
        private SshIdentification _localIdentification;
        private SshIdentification _remoteIdentification;
        private MacAlgorithm _localMac = MacAlgorithm.None;
        private EncryptionAlgorithm _localEncryption = EncryptionAlgorithm.None;
        private MacAlgorithm _remoteMac = MacAlgorithm.None;
        private EncryptionAlgorithm _remoteEncryption = EncryptionAlgorithm.None;
        private readonly SshOptions _options = SshOptions.DefaultInstance;
        internal HostKey _hostKey; //TODO: not be internal

        private ExchangeContext _exchangeContext;

        /// <summary>
        /// Gets the peer state.
        /// </summary>
        public PeerState State => _state;

        /// <summary>
        /// Gets the local identification information.
        /// </summary>
        public SshIdentification LocalIdentification => _localIdentification;

        /// <summary>
        /// Gets the remote identification information.
        /// </summary>
        public SshIdentification RemoteIdentification => _remoteIdentification;

        /// <summary>
        /// Gets the <see cref="PeerMode"/> of the peer.
        /// </summary>
        public PeerMode Mode => _mode;

        #region Key Exchange
        
        /// <summary>
        /// Exchanges keys with the 
        /// </summary>
        /// <returns></returns>
        public async ValueTask ExchangeKeysAsync()
        {
            // the peer must be in version exchange to do this
            if (_state != PeerState.KeyExchange) {
                throw new InvalidOperationException("The peer must be in the key exchange state");
            }
            
            // encode and flush our message
            KeyInitializationMessage outKeyInitMsg = default;
            outKeyInitMsg.KeyExchangeAlgorithms = _options.KeyExchangeAlgorithms.Select(k => k.Name).ToList();
            outKeyInitMsg.ServerHostKeyAlgorithms = new List<string>() { "ssh-rsa" };
            outKeyInitMsg.EncryptionAlgorithmsClientToServer = new List<string>() { "aes128-cbc" }; //TODO
            outKeyInitMsg.EncryptionAlgorithmsServerToClient = new List<string>() { "aes128-cbc" }; //TODO
            outKeyInitMsg.MacAlgorithmsClientToServer = new List<string>() { "hmac-sha1" }; //TODO
            outKeyInitMsg.MacAlgorithmsServerToClient = new List<string>() { "hmac-sha1" }; //TODO
            outKeyInitMsg.CompressionAlgorithmsClientToServer = new List<string>() { "none" }; //TODO
            outKeyInitMsg.CompressionAlgorithmsServerToClient = new List<string>() { "none" }; //TODO
            outKeyInitMsg.LanguagesClientToServer = new List<string>();
            outKeyInitMsg.LanguagesServerToClient = new List<string>();
            outKeyInitMsg.GenerateCookie();
            
            if (_mode == PeerMode.Client) {
                _exchangeContext.ClientInitPayload = MessageUtilities.MessageToMemory<KeyInitializationMessage, KeyInitializationMessage.Encoder>(in outKeyInitMsg);
            } else if (_mode == PeerMode.Server) {
                _exchangeContext.ServerInitPayload = MessageUtilities.MessageToMemory<KeyInitializationMessage, KeyInitializationMessage.Encoder>(in outKeyInitMsg);
            } else {
                throw new NotImplementedException();
            }

            await WritePacketAsync<KeyInitializationMessage, KeyInitializationMessage.Encoder>(outKeyInitMsg)
                .ConfigureAwait(false);

            ExchangeAlgorithm exchangeAlgo = null;

            while (true) {
                var packet = await ReadPacketAsync().ConfigureAwait(false);

                if (packet == null) {
                    throw new EndOfStreamException("The end of stream was reached before keys could be exchanged");
                }

                if (!packet.Value.TryGetMessageNumber(out MessageNumber num)) {
                    throw new Exception("The peer sent an invalid message");
                }

                // process key initialization
                if (num == MessageNumber.KeyInitialization) {
                    if (exchangeAlgo != null) {
                        throw new InvalidOperationException("The peer sent another key initialization");
                    }

                    using (packet) {
                        if (!packet.Value.TryDecode<KeyInitializationMessage, KeyInitializationMessage.Decoder>(out KeyInitializationMessage keyInitMsg)) {
                            throw new InvalidDataException("The peer sent an invalid key initialization packet");
                        }

                        // depending our peer mode we need to store the received key init for exchange algorithms later
                        if (_mode == PeerMode.Client) {
                            _exchangeContext.ServerInitPayload = packet.Value.ToMemoryPacket().Memory;
                        } else if (_mode == PeerMode.Server) {
                            _exchangeContext.ClientInitPayload = packet.Value.ToMemoryPacket().Memory;
                        } else {
                            throw new NotImplementedException();
                        }
                    }

                    exchangeAlgo = new DiffieHellmanGroupExchangeAlgorithm();

                    //TODO: cancellation
                    await exchangeAlgo.StartAsync(this, _exchangeContext).ConfigureAwait(false);
                    
                    continue;
                }

                // process exchange packets
                if ((byte)num >= 30 || (byte)num <= 49) {
                    if (exchangeAlgo == null) {
                        throw new InvalidOperationException("The peer sent an exchange packet before key initialization");
                    }

                    // Process the exchange packet, if this completes the exchange we send our new keys and wait for our peers
                    ExchangeOutput exchangeOutput = await exchangeAlgo.ProcessAsync(this, packet.Value).ConfigureAwait(false);
                    
                    if (exchangeOutput != null) {
                        // Send new keys message
                        GenericMessage newKeysMsg = new GenericMessage();
                        newKeysMsg.Number = MessageNumber.NewKeys;
                        
                        await WritePacketAsync<GenericMessage, GenericMessage.Encoder>(newKeysMsg)
                            .ConfigureAwait(false);
                        
                        // Wait for new keys message, or possibly a disconnect
                        using (packet = await ReadPacketAsync().ConfigureAwait(false)) {
                            if (packet == null) {
                                throw new EndOfStreamException("The end of stream was reached before keys could be exchanged");
                            }
                            
                            if (!packet.Value.TryGetMessageNumber(out num)) {
                                throw new Exception("The peer sent an invalid message");
                            }

                            if (num == MessageNumber.NewKeys) {
                                var localAes = Aes.Create();
                                localAes.Key = exchangeOutput.DeriveBytes(128 / 8, ExchangeKey.ClientToServer | ExchangeKey.EncryptionKey);
                                _localEncryption = new SymmetricEncryptionAlgorithm(localAes, CipherMode.ECB);
                                
                                var remoteAes = Aes.Create();
                                remoteAes.Key = exchangeOutput.DeriveBytes(128 / 8, ExchangeKey.ServerToClient | ExchangeKey.EncryptionKey);
                                _remoteEncryption = new SymmetricEncryptionAlgorithm(remoteAes, CipherMode.ECB);
                                
                                _state = PeerState.Open;
                                return;
                            } else {
                                throw new Exception("The peer sent an invalid key exchange response");
                            }
                        }
                    }
                }
            }

        }
        #endregion

        #region Identification
        /// <summary>
        /// Exchanges the version by writing and reading the identification string.
        /// </summary>
        /// <param name="localIdentification">The local version.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>The remote SSH identification data.</returns>
        public async ValueTask<SshIdentification> ExchangeIdentificationAsync(SshIdentification localIdentification)
        {
            // the peer must be in version exchange to do this
            if (_state != PeerState.IdentificationExchange) {
                throw new InvalidOperationException("The peer must be in the version exchange state");
            }
            
            // create the timeout cancellation source that will dispose the peer
            CancellationTokenRegistration timeoutRegistration = default;

            if (_options.IdentificationExchangeTimeout != null) {
                CancellationTokenSource timeoutTokenSource =
                    new CancellationTokenSource(_options.IdentificationExchangeTimeout.Value);
                timeoutRegistration = timeoutTokenSource.Token.Register((o) => {
                    ((Peer) o).Dispose(new TimeoutException("Timeout while exchanging identification lines"));
                }, this);
            }
            
            // write identification
            _localIdentification = localIdentification;
            await WriteIdentificationAsync(localIdentification).ConfigureAwait(false);

            // read the identification
            SshIdentification? remoteIdentification = await ReadIdentificationAsync().ConfigureAwait(false);

            if (remoteIdentification == null) {
                Exception exception = new Exception("The peer was closed while exchanging identification");
                Dispose(exception);
                throw exception;
            }
            
            await timeoutRegistration.DisposeAsync();
            //TODO: there is probably a race condition here
            
            // if the identification was read lets validate it before continuing
            _remoteIdentification = remoteIdentification.Value;
            
            if (_remoteIdentification.ProtocolVersion != "2.0") {
                NotSupportedException exception = new NotSupportedException("The opposing protocol version is unsupported");
                Dispose(exception);
                throw exception;
            }

            if (_mode == PeerMode.Client) {
                _exchangeContext.ClientIdentification = localIdentification;
                _exchangeContext.ServerIdentification = remoteIdentification.Value;
            } else if (_mode == PeerMode.Server) {
                _exchangeContext.ClientIdentification = remoteIdentification.Value;
                _exchangeContext.ServerIdentification = localIdentification;
            } else {
                throw new NotImplementedException();
            }

            _state = PeerState.KeyExchange;
            return _remoteIdentification;
        }

        private bool TryReadIdentification(ReadOnlySpan<byte> identificationBuffer, ref SshIdentification identification)
        {
            // validate: we need both '\r' and '\n' to be considered valid
            if (identificationBuffer[identificationBuffer.Length - 2] != '\r') {
                Debug.Fail("The identification line is not CRLF");
                return false;
            }

            // validate: must be at least "SSH-2.0-\r\n" which is 10 bytes
            if (identificationBuffer.Length < 10) {
                Debug.Fail("The identification line is too small");
                return false;
            }

            // validate: must start with "SSH-"
            if (identificationBuffer[0] != (byte)'S' || identificationBuffer[1] != (byte)'S'
                || identificationBuffer[2] != (byte)'H' || identificationBuffer[3] != (byte)'-') {
                Debug.Fail("The identification line prefix is invalid");
                return false;
            }

            identificationBuffer = identificationBuffer.Slice(4);

            // next we check the protocol version, 99.9% of the time this is 2.0 - so lets check that
            // and if so set to a string literal which saves pointless searching and allocations
            string protocolVersion;

            if (identificationBuffer[0] != (byte)'2' || identificationBuffer[1] != (byte)'.'
                || identificationBuffer[2] != (byte)'0' || identificationBuffer[3] != (byte)'-') {
                protocolVersion = "2.0";
                identificationBuffer = identificationBuffer.Slice(4);
            } else {
                // get protocol version
                int dashPos = identificationBuffer.IndexOf((byte)'-');

                if (dashPos == -1) {
                    Debug.Fail("The identification line cannot scan the version");
                    return false;
                }

                protocolVersion = Encoding.ASCII.GetString(identificationBuffer.Slice(0, dashPos));
                identificationBuffer = identificationBuffer.Slice(dashPos + 1);
            }

            // get the software version
            string softwareVersion;
            string comments = null;
            int spPos = identificationBuffer.IndexOf((byte)' ');

            if (spPos != -1) {
                softwareVersion = Encoding.ASCII.GetString(identificationBuffer.Slice(0, spPos));
                identificationBuffer = identificationBuffer.Slice(spPos + 1);
                comments = Encoding.ASCII.GetString(identificationBuffer.Slice(0, identificationBuffer.Length - 2));
            } else {
                softwareVersion = Encoding.ASCII.GetString(identificationBuffer.Slice(0, identificationBuffer.Length - 2));
            }

            identification = new SshIdentification(protocolVersion, softwareVersion, comments);
            return true;
        }

        private bool TryReadIdentification(ReadOnlySequence<byte> sequence, SequencePosition lrPos, ref SshIdentification identification)
        {
            // get the full sequence for identification line
            ReadOnlySequence<byte> identificationSeq = sequence.Slice(sequence.Start, sequence.GetPosition(0, lrPos));

            if (identificationSeq.Length > 255) {
                throw new InvalidDataException("The peer sent an oversized identification line");
            }

            // either copy if buffer is made of many components or use a slice of first component
            if (identificationSeq.IsSingleSegment) {
                //TODO: is this necessary? concerned that the first segment might be larger than the entire length
                return TryReadIdentification(identificationSeq.FirstSpan.Slice(0, (int)identificationSeq.Length), ref identification);
            } else {
                Span<byte> identificationBuffer = stackalloc byte[255];
                identificationSeq.CopyTo(identificationBuffer);
                return TryReadIdentification(identificationBuffer, ref identification);
            }
        }

        private async ValueTask<SshIdentification?> ReadIdentificationAsync()
        {
            // keep reading data until we receive CRLF unless 255 bytes of data arrives first
            while (true) {
                // if closing/closed we are completing/completed
                if (_state == PeerState.Closing || _state == PeerState.Closed)
                    return null;

                var result = await _reader.ReadAsync().ConfigureAwait(false);

                // look for carriage return
                var lrPos = result.Buffer.PositionOf((byte)'\n');

                if (lrPos.HasValue) {
                    SshIdentification identification = default;

                    try {
                        if (TryReadIdentification(result.Buffer, result.Buffer.GetPosition(1, lrPos.Value), ref identification)) {
                            return identification;
                        } else {
                            // the RFC allows CRLF lines of UTF-8 to be sent up to 255 bytes prior to the identification line
                            // this must be one of them, so process and move
                        }
                    } finally {
                        _reader.AdvanceTo(result.Buffer.GetPosition(1, lrPos.Value));
                    }
                } else {
                    // no '\n' found in any of the buffer
                    _reader.AdvanceTo(result.Buffer.Start, result.Buffer.End);
                }
                
                // if completed then we need to bubble up
                if (result.IsCompleted) {
                    return null;
                }
                
                // if we didn't find the identification and we've reached 255 bytes we've reached the RFC limit
                if (result.Buffer.Length >= 255) {
                    return null;
                }
            }
        }

        private async ValueTask WriteIdentificationAsync(SshIdentification identification)
        {
            // calculate total length
            int totalLength = 8 // SSH-2.0-
                + Encoding.ASCII.GetByteCount(identification.SoftwareVersion)
                + (string.IsNullOrEmpty(identification.Comments) ? 0 : Encoding.ASCII.GetByteCount(identification.Comments) + 1)
                + 2; // <CR> <LF>

            if (totalLength > 255) {
                throw new ArgumentException("The identification string is too long", nameof(identification));
            }

            // get a buffer to store into
            Memory<byte> buffer = _writer.GetMemory(255);

            // write the initial part always (8 bytes)
            int offset = 8;
            Encoding.ASCII.GetBytes("SSH-2.0-", buffer.Span.Slice(0, 8));

            // write the software version
            offset += Encoding.ASCII.GetBytes(LocalIdentification.SoftwareVersion, buffer.Span.Slice(8));

            // write the comments if available
            if (!string.IsNullOrEmpty(identification.Comments)) {
                buffer.Span[offset++] = (byte)' ';
                offset += Encoding.ASCII.GetBytes(LocalIdentification.Comments, buffer.Span.Slice(offset));
            }

            // write CR LF
            buffer.Span[offset++] = (byte)'\r';
            buffer.Span[offset++] = (byte)'\n';

            _writer.Advance(offset);
            await _writer.FlushAsync();
        }
        #endregion

        #region Reading
        /// <summary>
        /// Reads a packet from the peer, handles encryption and integrity.
        /// </summary>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>The packet, SHOULD be advanced before reading next packet.</returns>
        public async ValueTask<IncomingPacket?> ReadPacketAsync(CancellationToken cancellationToken = default)
        {
            //TODO: cancellation

            static (bool Done, IncomingPacket Packet, SequencePosition Examined) Process(Peer peer, ReadOnlySequence<byte> buffer)
            {
                //TODO: handle encryption
                SequenceReader<byte> reader = new SequenceReader<byte>(buffer);

                if (!reader.TryRead(out PacketHeader header))
                    return (false, default, reader.Position);

                if (header.Length + 4 > peer._options.MaximumPacketSize)
                    throw new InvalidDataException("The peer attempted to send a packet which is too big");

                // make sure we have the whole message + padding
                // the header length includes the padding length which we just read
                if (reader.Remaining < header.Length - 1) {
                    reader.Advance(Math.Min(reader.Remaining, header.Length));
                    return (false, default, reader.Position);
                }

                reader.Advance(Math.Min(reader.Remaining, header.Length));

                //TODO: handle integrity MAC here

                int messageLength = (int)(header.Length - 1 /* padding length */ - header.PaddingLength);
                return (true, new IncomingPacket(header, buffer.Slice(PacketHeader.Size, messageLength), peer, reader.Position), reader.Position);
            }

            while (true) {
                // if closing/closed we are completing/completed
                if (_state == PeerState.Closing || _state == PeerState.Closed)
                    throw new NotImplementedException(); //TODO

                ReadResult readResult = await _reader.ReadAsync().ConfigureAwait(false);
                
                var processResult = Process(this, readResult.Buffer);
                
                if (processResult.Done) {
                    // we do not need to advance here as IncomingPacket.Advance does it for us
                    return processResult.Packet;
                }
                
                _reader.AdvanceTo(readResult.Buffer.Start, processResult.Examined);

                // if completed we need to bubble up after processing
                if (readResult.IsCompleted) {
                    return null;
                }
            }
        }
        #endregion

        #region Writing
        /// <summary>
        /// Writes a packet to the peer without specifying a encoder type, this will result in additional allocations.
        /// </summary>
        /// <typeparam name="TMessage">The message.</typeparam>
        /// <param name="message">The message.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns></returns>
        public ValueTask WritePacketAsync<TMessage>(TMessage message, CancellationToken cancellationToken = default)
            where TMessage: IPacketMessage<TMessage>
        {
            return WritePacketAsync(message, message.CreateEncoder(), cancellationToken);
        }

        /// <summary>
        /// Writes a packet to the peer.
        /// </summary>
        /// <typeparam name="TMessage">The message.</typeparam>
        /// <typeparam name="TMessageEncoder">The encoder.</typeparam>
        /// <param name="message">The message.</param>
        /// <param name="encoder">The encoder.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns></returns>
        public void WritePacket<TMessage, TMessageEncoder>(TMessage message, TMessageEncoder encoder = default, CancellationToken cancellationToken = default)
            where TMessage : IPacketMessage<TMessage>
            where TMessageEncoder : IMessageEncoder<TMessage>
        {
            static void WriteHeader(IBufferWriter<byte> writer, PacketHeader header)
            {
                Span<byte> bytes = writer.GetSpan(PacketHeader.Size);
                header.TryWriteBytes(bytes);
                writer.Advance(PacketHeader.Size);
            }

            static void WritePadding(IBufferWriter<byte> writer, int count)
            {
                Debug.Assert(count <= 255);

                Span<byte> paddingBytes = writer.GetSpan(count);
                paddingBytes.Slice(0, count)
                    .Fill(0);
                writer.Advance(count);
            }

            // calculate lengths
            uint messageLength = message.GetByteCount(); // message length, includes the message number already
            uint paddingLength = (byte)(8 - ((messageLength + 1 + 4) % 8)); // padding is entire packet in block of 8

            //TODO: the packet length must be at least 16 bytes
            //TODO: this is a dirty hack for small padding
            if (paddingLength < 4) {
                paddingLength += 8;
            }

            uint packetLength = messageLength + 1 + paddingLength; // packet length doesn't include itself or mac

            PacketHeader header = new PacketHeader() {
                Length = packetLength,
                PaddingLength = (byte)paddingLength
            };

            WriteHeader(_writer, header);

            // encode message piece by piece
            bool moreData = false;

            do {
                moreData = !encoder.Encode(message, _writer);
            } while (moreData);

            WritePadding(_writer, header.PaddingLength);
        }

        /// <summary>
        /// Writes a packet to the peer.
        /// </summary>
        /// <typeparam name="TMessage">The message.</typeparam>
        /// <typeparam name="TMessageEncoder">The encoder.</typeparam>
        /// <param name="message">The message.</param>
        /// <param name="encoder">The encoder.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns></returns>
        public async ValueTask WritePacketAsync<TMessage, TMessageEncoder>(TMessage message, TMessageEncoder encoder = default, CancellationToken cancellationToken = default)
            where TMessage : IPacketMessage<TMessage>
            where TMessageEncoder : IMessageEncoder<TMessage>
        {
            static void WriteHeader(IBufferWriter<byte> writer, PacketHeader header)
            {
                Span<byte> bytes = writer.GetSpan(PacketHeader.Size);
                header.TryWriteBytes(bytes);
                writer.Advance(PacketHeader.Size);
            }
            
            static void WritePadding(IBufferWriter<byte> writer, int count)
            {
                Debug.Assert(count <= 255);

                Span<byte> paddingBytes = writer.GetSpan(count);
                paddingBytes.Slice(0, count)
                    .Fill(0);
                writer.Advance(count);
            }

            // calculate lengths
            uint messageLength = message.GetByteCount(); // message length, includes the message number already
            uint paddingLength = (byte)(8 - ((messageLength + 1 + 4) % 8)); // padding is entire packet in block of 8

            //TODO: the packet length must be at least 16 bytes
            //TODO: this is a dirty hack for small padding
            if (paddingLength < 4) {
                paddingLength += 8;
            }

            uint packetLength = messageLength + 1 + paddingLength; // packet length doesn't include itself or mac

            PacketHeader header = new PacketHeader() {
                Length = packetLength,
                PaddingLength = (byte)paddingLength
            };

            WriteHeader(_writer, header);

            // encode message piece by piece
            bool moreData = false;

            do {
                if (moreData) {
                    await _writer.FlushAsync(cancellationToken).ConfigureAwait(false);
                }

                moreData = !encoder.Encode(message, _writer);
            } while (moreData);

            WritePadding(_writer, header.PaddingLength);
            await _writer.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        #endregion

        internal void AdvanceTo(SequencePosition position)
        {
            _reader.AdvanceTo(position);
        }

        private async ValueTask DisconnectAsync(Exception exception = null)
        {
            // gracefully close the peer
            //TODO: if connected send disconnect message
            
            _state = PeerState.Closing;
            await _reader.CompleteAsync(exception).ConfigureAwait(false);
            await _writer.CompleteAsync(exception).ConfigureAwait(false);
            _state = PeerState.Closed;
        }

        private void Dispose(Exception exception = null)
        {
            // terminate the peer
            _state = PeerState.Closing;
            _reader.Complete(exception);
            _writer.Complete(exception);
            _state = PeerState.Closed;
        }

        internal Peer(PeerMode mode, PipeReader pipeReader, PipeWriter pipeWriter)
        {
            _reader = pipeReader;
            _mode = mode;
            _writer = pipeWriter;
            _exchangeContext.Peer = this;

            //TODO: get key store elsewhere
            RSA rsa;

            if (!File.Exists("hostkey")) {
                rsa = RSA.Create(2048);
                File.WriteAllBytes("hostkey", rsa.ExportRSAPrivateKey());
            } else {
                rsa = RSA.Create();
                rsa.ImportRSAPrivateKey(File.ReadAllBytes("hostkey").AsSpan(), out int _);
            }

            _hostKey = new RsaHostKey(rsa);
        }
    }
}
