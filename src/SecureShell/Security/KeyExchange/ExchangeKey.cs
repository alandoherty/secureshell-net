using System;

namespace SecureShell.Security.KeyExchange
{
    /// <summary>
    /// Represents an exchange key and direction.
    /// </summary>
    [Flags]
    public enum ExchangeKey
    {
        ClientToServer = 1,
        ServerToClient = 2,
        
        InitializationVector = 4,
        EncryptionKey = 8,
        IntegrityKey = 16
    }
}