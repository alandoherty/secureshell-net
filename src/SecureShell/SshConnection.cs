using SecureShell.Transport;
using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Net;
using System.Text;

namespace SecureShell
{
    /// <summary>
    /// Represents a SSH connection accepted via a <see cref="SshListener"/>.
    /// </summary>
    public class SshConnection : Peer
    {
        private EndPoint _localEndpoint;
        private EndPoint _remoteEndpoint;
        private SshListener _listener;

        /// <summary>
        /// Gets the local endpoint.
        /// </summary>
        public EndPoint LocalEndpoint => _localEndpoint;

        /// <summary>
        /// Gets the remote endpoint.
        /// </summary>
        public EndPoint RemoteEndpoint => _remoteEndpoint;

        /// <summary>
        /// Gets the listener which accepted this connection.
        /// </summary>
        public SshListener Listener => _listener;

        internal SshConnection(SshListener listener, EndPoint localEndpoint, EndPoint remoteEndpoint, PipeReader pipeReader, PipeWriter pipeWriter) : base(PeerMode.Server, pipeReader, pipeWriter)
        {
            _listener = listener;
            _localEndpoint = localEndpoint;
            _remoteEndpoint = remoteEndpoint;
        }
    }
}
