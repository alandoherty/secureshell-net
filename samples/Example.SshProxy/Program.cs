using System;
using System.IO;
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
                client1.NoDelay = true;

                try {
                    TcpClient client2 = new TcpClient("127.0.0.1", 1337);
                    client2.NoDelay = true;

                    NetworkStream stream1 = client1.GetStream();
                    NetworkStream stream2 = client2.GetStream();

                    await Task.WhenAny(CopyStreamInChunkAsync(4, stream1, stream2), CopyStreamInChunkAsync(8, stream2, stream1));
                } catch (Exception ex) {
                    Console.WriteLine(ex.Message);
                } finally {
                    client1.Dispose();
                }
            }

            await Task.Delay(-1);
        }

        static async Task CopyStreamInChunkAsync(int chunkSize, Stream from, Stream to)
        {
            byte[] chunkBuffer = new byte[chunkSize];

            while (true) {
                int count = await from.ReadAsync(chunkBuffer.AsMemory());

                if (count == 0)
                    return;

                await Task.Delay(1000);
                await to.WriteAsync(chunkBuffer.AsMemory(0, count));
                await to.FlushAsync();
            }
        }
    }
}