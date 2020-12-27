using System;
using System.Buffers;
using System.Collections.Generic;
using System.Text;

namespace BattleCrate.Filesystem.Ssh.Protocol
{
    public interface IPacketEncoder<TMessage>
    {
        bool Encode(ref TMessage message, IBufferWriter<byte> writer);
    }
}
