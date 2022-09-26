using SecureShell.Transport;
using System;
using System.Collections.Generic;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace SecureShell
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
        /// <returns></returns>
        public ValueTask<SshConnection> GetConnectionAsync()
        {
            return GetConnectionAsync(SshIdentification.Default);
        }

        /// <summary>
        /// Gets the connection by performing version exchange and initial key exchange.
        /// </summary>
        /// <param name="identification">The identification.</param>
        /// <returns></returns>
        public async ValueTask<SshConnection> GetConnectionAsync(SshIdentification identification)
        {
            if (_connection == null)
                throw new InvalidOperationException("The connection context is invalid");

            // Identification exchange
            await _connection.ExchangeIdentificationAsync(identification);

            // Exchange initial keys
            await _connection.ExchangeKeysAsync();

            var packet = await _connection.ReadPacketAsync();
            
            throw new NotImplementedException();
        }

        internal SshConnectionContext(SshConnection connection)
        {
            _connection = connection;
        }
    }
}
