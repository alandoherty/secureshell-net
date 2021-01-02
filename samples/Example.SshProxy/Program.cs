using System;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace Example.SshProxy
{
    class Program
    {
        static async Task Main(string[] args)
        {
            TcpListener listener = new TcpListener(1338);
            listener.Start();

            while (true) {
                TcpClient client1 = listener.AcceptTcpClient();

                try {
                    TcpClient client2 = new TcpClient("127.0.0.1", 1337);

                    NetworkStream stream1 = client1.GetStream();
                    NetworkStream stream2 = client2.GetStream();

                    await Task.WhenAny(stream1.CopyToAsync(stream2, 2), stream2.CopyToAsync(stream1, 2));
                } catch (Exception ex) {
                    Console.WriteLine(ex.Message);
                } finally {
                    client1.Dispose();
                }
            }

            await Task.Delay(-1);
        }
    }
}