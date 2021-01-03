using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipelines;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using SecureShell.Integrity;
using SecureShell.Protocol;
using SecureShell.Protocol.Messages;

namespace SecureShell
{
    /// <summary>
    /// Represents a SSH2 peer and provides functionality to read/write packets. It handles the SSH Transport state, accepting services and processing data but does not deal with user authentication or other services.
    /// </summary>
    public class SshPeer
    {
        private PeerMode _mode;
        private PeerState _state = PeerState.IdentificationExchange;
        private PipeReader _reader;
        private PipeWriter _writer;
        private byte[] _headerBuffer = new byte[5];
        private SshIdentification _localIdentification;
        private SshIdentification _remoteIdentification;
        private MacAlgorithm _localMac = MacAlgorithm.None;
        private MacAlgorithm _remoteMac = MacAlgorithm.None;

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

        private void Read(in ReadOnlySequence<byte> seq)
        {
            SequenceReader<byte> reader = new SequenceReader<byte>(seq);
            
            // read header
            reader.TryRead(out PacketHeader header);

            // read message num
            reader.TryRead(out byte msgNum);

            if (msgNum == (byte)MessageNumber.KeyInitialization) {
                KeyInitializationMessage msg = default;
                KeyInitializationMessage.Decoder decoder = default;
                decoder.Decode(ref msg, ref reader);

                Console.WriteLine(string.Join(',', msg.KeyExchangeAlgorithms));
            }
            
            // advance past padding
            reader.Advance(header.PaddingLength);

            // read header
            bool a = reader.TryRead(out header);
        }
        
        /// <summary>
        /// Exchanges keys with the 
        /// </summary>
        /// <returns></returns>
        public async ValueTask ExchangeKeysAsync()
        {
            while (true) {
                ReadResult result = await _reader.ReadAsync();
                
                Read(result.Buffer);
            }
        }
        #endregion

        #region Identification
        /// <summary>
        /// Exchanges the version by writing and reading the identification string.
        /// </summary>
        /// <param name="localIdentification">The local version.</param>
        /// <returns>The remote SSH identification data.</returns>
        public async ValueTask<SshIdentification> ExchangeIdentificationAsync(SshIdentification localIdentification)
        {
            // the peer must be in version exchange to do this
            if (_state != PeerState.IdentificationExchange) {
                throw new InvalidOperationException("The peer must be in the version exchange state");
            }

            // write identification
            _localIdentification = localIdentification;
            await WriteIdentificationAsync(localIdentification);

            // read the identification
            _remoteIdentification = await ReadIdentificationAsync();

            if (_remoteIdentification.ProtocolVersion != "2.0") {
                NotSupportedException exception = new NotSupportedException("The opposing protocol version is unsupported");
                await CloseAsync(exception);
                throw exception;
            }

            return _remoteIdentification;
        }

        private bool TryReadIdentification(ReadOnlySpan<byte> identificationBuffer, ref SshIdentification identification)
        {
            // validate: we need both '\r' and '\n' to be considered valid
            if (identificationBuffer[identificationBuffer.Length - 2] != '\r') {
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
            ReadOnlySequence<byte> identificationSeq = sequence.Slice(sequence.Start, lrPos);

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

        private async ValueTask<SshIdentification> ReadIdentificationAsync()
        {
            // keep reading data until we receive CRLF unless 255 bytes of data arrives first
            while (true) {
                var result = await _reader.ReadAsync();

                // look for carriage return
                var lrPos = result.Buffer.PositionOf((byte)'\n');

                if (lrPos.HasValue) {
                    _reader.AdvanceTo(result.Buffer.GetPosition(1, lrPos.Value));

                    SshIdentification identification = default;

                    if (TryReadIdentification(result.Buffer, lrPos.Value, ref identification)) {
                        return identification;
                    } else {
                        // the RFC allows CRLF lines of UTF-8 to be sent up to 255 bytes prior to the identification line
                        // this must be one of them, so process and move
                    }
                } else {
                    // no '\n' found in any of the buffer
                    _reader.AdvanceTo(result.Buffer.Start, result.Buffer.End);
                }

                // if we didn't find the identification and we've reached 255 bytes we've reached the RFC limit
                if (result.Buffer.Length >= 255) {
                    throw new InvalidDataException("The peer sent an invalid or corrupt identification line");
                }
            }
        }
        #endregion

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

            if (buffer.Length < 255) {
                // if we got a buffer which was too small we need to do a less efficient process
                //TODO: this can be fixed with a less efficient implementation later
                throw new NotSupportedException("The identification buffer is too small");
            }

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

        /// <summary>
        /// Writes a header to the peer.
        /// </summary>
        /// <param name="header">The packet header.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns></returns>
        private async ValueTask WriteHeaderAsync(PacketHeader header, CancellationToken cancellationToken =default)
        {
            Memory<byte> memory = _writer.GetMemory(5);

            if (!header.TryWriteBytes(memory.Span))
                throw new Exception("Failed to write header to buffer");

            _writer.Advance(5);
            await _writer.FlushAsync();
        }

        private async ValueTask CloseAsync(Exception exception = null)
        {
            _state = PeerState.Closed;
            await _reader.CompleteAsync(exception);
            await _writer.CompleteAsync(exception);
        }

        internal SshPeer(PeerMode mode, PipeReader pipeReader, PipeWriter pipeWriter)
        {
            _reader = pipeReader;
            _mode = mode;
            _writer = pipeWriter;
        }
    }
}
