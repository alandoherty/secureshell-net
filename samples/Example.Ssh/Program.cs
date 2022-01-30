using SecureShell;
using SecureShell.Transport;
using System;
using System.Net;
using System.Threading.Tasks;

namespace Example.Ssh
{
    class Program
    {
        static async Task ClientAsync()
        {
            while (true) {

                await Task.Delay(1000);

                Renci.SshNet.SshClient sshClient = new Renci.SshNet.SshClient("127.0.0.1", 1337, "alan", "potato");
                await sshClient.ConnectAsync(default);
            }
        }

        static async Task AcceptAsync(SshConnectionContext ctx)
        {
            SshConnection connection;

            try {
                connection = await ctx.GetConnectionAsync();
                
            } catch (Exception ex) {
                Console.Error.WriteLine("SERVER: " + ex.ToString());
            }
        }

        static async Task Main(string[] args)
        {
            //SshClient client = new SshClient();
            //await client.ConnectAsync();
            Task clientTask = ClientAsync();
            await clientTask;
            // create the listener
            SshListener listener = new SshListener(new IPEndPoint(IPAddress.Any, 1337));
            listener.Start();
            
            // loop accepting connections
            while(true) {
                Task<SshConnectionContext> acceptTask = listener.AcceptAsync();

                if (await Task.WhenAny(clientTask, acceptTask) == acceptTask) {
                    _ = AcceptAsync(await acceptTask);
                } else {
                    await clientTask;
                }
            }
        }
    }
}
