using System;
using System.Buffers;
using System.Collections.Generic;
using System.Text;

namespace BattleCrate.Filesystem.Ssh.Protocol
{
    public interface IPacketDecoder<TMessage>
    {
        bool Decode(ref TMessage message, ReadOnlySequence<byte> sequence, out SequencePosition examined, out SequencePosition consumed);
    }
}
