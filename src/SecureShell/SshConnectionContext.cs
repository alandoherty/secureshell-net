using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace BattleCrate.Filesystem.Ssh
{
    /// <summary>
    /// Represents an incoming connection that must 
    /// </summary>
    /// TODO: cancellation
    public readonly struct SshConnectionContext
    {
        private readonly SshConnection _connection;

        /// <summary>
        /// Gets the local endpoint of the connection.
        /// </summary>
        public EndPoint LocalEndpoint {
            get {
                return _connection.LocalEndpoint;
            }
        }

        /// <summary>
        /// Gets the remote endpoint of the connection.
        /// </summary>
        public EndPoint RemoteEndpoint {
            get {
                return _connection.RemoteEndpoint;
            }
        }

        /// <summary>
        /// Gets the listener that accepted the connection.
        /// </summary>
        public SshListener Listener {
            get {
                return _connection.Listener;
            }
        }

        /// <summary>
        /// Gets the connection by performing version exchange and initial key exchange.
        /// </summary>
        /// <param name="progress">A handler for progress, will emit <see cref="PeerState.IdentificationExchange"/>, <see cref="PeerState.KeyExchange"/> and <see cref="PeerState.Open"/>.</param>
        /// <returns></returns>
        public ValueTask<SshConnection> GetConnectionAsync(IProgress<PeerState> progress = null)
        {
            return GetConnectionAsync(SshIdentification.Default, progress);
        }

        /// <summary>
        /// Gets the connection by performing version exchange and initial key exchange.
        /// </summary>
        /// <param name="identification">The identification.</param>
        /// <param name="progress">A handler for progress, will emit <see cref="PeerState.IdentificationExchange"/>, <see cref="PeerState.KeyExchange"/> and <see cref="PeerState.Open"/>.</param>
        /// <returns></returns>
        public async ValueTask<SshConnection> GetConnectionAsync(SshIdentification identification, IProgress<PeerState> progress = null)
        {
            if (_connection == null)
                throw new InvalidOperationException("The connection context is invalid");

            // identification exchange
            progress.Report(PeerState.IdentificationExchange);
            await _connection.ExchangeIdentificationAsync(identification);

            //TODO: exchange keys
            progress.Report(PeerState.KeyExchange);
            await _connection.ExchangeKeysAsync();
            throw new NotImplementedException();
        }

        internal SshConnectionContext(SshConnection connection)
        {
            _connection = connection;
        }
    }
}
