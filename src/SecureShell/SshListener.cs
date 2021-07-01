using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace SecureShell
{
    /// <summary>
    /// Accepts <see cref="SshConnection"/> peers.
    /// </summary>
    public class SshListener
    {
        private readonly Socket _socket;
        private readonly EndPoint _endpoint;

        /// <summary>
        /// Gets the local endpoint.
        /// </summary>
        public EndPoint Endpoint {
            get {
                return _endpoint;
            }
        }

        /// <summary>
        /// Accepts a connection from the endpoint.
        /// </summary>
        /// <returns></returns>
        public async Task<SshConnectionContext> AcceptAsync()
        {
            // accept a socket
            Socket socket = await _socket.AcceptAsync();

            // create stream
            NetworkStream stream = new NetworkStream(socket);

            // create pipes
            PipeReader reader = PipeReader.Create(stream, new StreamPipeReaderOptions() {
            });
            PipeWriter writer = PipeWriter.Create(stream);

            // create the connection and return a context
            SshConnection conn = new SshConnection(this, socket.LocalEndPoint, socket.RemoteEndPoint, reader, writer);

            return new SshConnectionContext(conn);
        }

        /// <summary>
        /// Starts listening for connections.
        /// </summary>
        /// <param name="backlog">The backlog.</param>
        public void Start(int backlog = 8)
        {
            _socket.Listen(backlog);
        }

        /// <summary>
        /// Stops listening for connections.
        /// </summary>
        public void Stop()
        {
            _socket.Close();
        }

        /// <summary>
        /// Creates a new listener from a URI. The supported schemes are unix:// and tcp://.
        /// </summary>
        /// <param name="uri">The URI.</param>
        public SshListener(Uri uri)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Creates a new listener from a URI. The supported schemes are unix:// and tcp://.
        /// </summary>
        /// <param name="uri">The URI.</param>
        public SshListener(string uri)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Creates a new listener from an endpoint. The supported endpoints are <see cref="IPEndPoint"/> and <see cref="UnixDomainSocketEndPoint"/>.
        /// </summary>
        /// <param name="endpoint">The endpoint.</param>
        public SshListener(EndPoint endpoint)
        {
            _endpoint = endpoint;

            if (endpoint is UnixDomainSocketEndPoint) {
                _socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Tcp);
                _socket.Bind(endpoint);
            } else if (endpoint is IPEndPoint ipEndpoint) {
                _socket = new Socket(ipEndpoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                _socket.Bind(endpoint);
            } else {
                throw new NotSupportedException("The provided endpoint is not supported");
            }
        }
    }
}
