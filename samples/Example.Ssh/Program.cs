using BattleCrate.Filesystem.Ssh;
using System;
using System.Net;
using System.Threading.Tasks;

namespace Example.Ssh
{
    class Program
    {
        static async Task AcceptAsync(SshConnectionContext ctx)
        {
            var conn = await ctx.GetConnectionAsync(new Progress<PeerState>(p => Console.WriteLine(p)));
        }

        static async Task Main(string[] args)
        {
            // create the listener
            SshListener listener = new SshListener(new IPEndPoint(IPAddress.Loopback, 1337));
            listener.Start();

            // loop accepting connections
            while(true) {
                var ctx = await listener.AcceptAsync();
                _ = AcceptAsync(ctx);
            }
        }
    }
}
