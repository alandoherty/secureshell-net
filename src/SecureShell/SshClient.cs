using SecureShell.Transport;
using System.IO.Pipelines;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace SecureShell
{
    public class SshClient 
    {
        Peer peer;

        public async Task ConnectAsync()
        {
            TcpClient client = new TcpClient("198.24.164.202", 22);

            // create stream
            NetworkStream stream = client.GetStream();

            // create pipes
            PipeReader reader = PipeReader.Create(stream, new StreamPipeReaderOptions() {
            });
            PipeWriter writer = PipeWriter.Create(stream);


            peer = new Peer(PeerMode.Client, reader, writer);
            await peer.ExchangeIdentificationAsync(new SshIdentification("Alware"));
            await peer.ExchangeKeysAsync();
        }
    }
}