using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace BattleCrate.Filesystem.Ssh.Protocol.Messages
{
    public struct KeyInitializationMessage : IPacketMessage<KeyInitializationMessage>
    {

        public int GetByteCount()
        {
            throw new NotImplementedException();
        }

        public ValueTask ReadAsync(PipeReader reader)
        {
            throw new NotImplementedException();
        }

        public ValueTask WriteAsync(PipeWriter writer)
        {
            throw new NotImplementedException();
        }
    }
}
