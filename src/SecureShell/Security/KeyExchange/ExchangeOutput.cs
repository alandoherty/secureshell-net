using System;
using System.Buffers;
using System.Numerics;
using System.Security.Cryptography;
using SecureShell.Transport.Utilities;

namespace SecureShell.Security.KeyExchange
{
    /// <summary>
    /// The output from a key exchange.
    /// </summary>
    public class ExchangeOutput
    {
        private readonly HashAlgorithm _hashAlg;
        
        /// <summary>
        /// Gets the character that seasons the encryption key, see RFC 4253 7.2.
        /// </summary>
        /// <returns>The character.</returns>
        private char GetKeyCharacter(ExchangeKey key)
        {
            // The derived keys are always unidirectional, 
            if ((key & ExchangeKey.ClientToServer) != 0 && (key & ExchangeKey.ServerToClient) != 0) {
                throw new ArgumentException("The exchange key cannot be bidirectional", nameof(key));
            }

            if ((key & ExchangeKey.InitializationVector) != 0) {
                if ((key & ExchangeKey.ClientToServer) != 0)
                    return 'A';
                if ((key & ExchangeKey.ServerToClient) != 0)
                    return 'B';
            }
            
            if ((key & ExchangeKey.EncryptionKey) != 0) {
                if ((key & ExchangeKey.ClientToServer) != 0)
                    return 'C';
                if ((key & ExchangeKey.ServerToClient) != 0)
                    return 'D';
            }

            if ((key & ExchangeKey.IntegrityKey) != 0) {
                if ((key & ExchangeKey.ClientToServer) != 0)
                    return 'E';
                if ((key & ExchangeKey.ServerToClient) != 0)
                    return 'F';
            }

            // We got here because we either had no key selector or no direction selector, or some weird enum issue
            throw new ArgumentException("The exchange key combination is not valid", nameof(key));
        }
        
        /// <summary>
        /// Derive the requested number of bytes for the specified key.
        /// </summary>
        /// <param name="count">The buffer count.</param>
        /// <param name="key">The exchange key to derive.</param>
        /// <returns>The derivation buffer.</returns>
        public byte[] DeriveBytes(int count, ExchangeKey key)
        {
            byte[] arr = new byte[count];
            
            if (!TryDeriveBytes(arr.AsSpan(), key)) {
                throw new CryptographicException("Unexpected error deriving exchange keys");
            }

            return arr;
        }
        
        /// <summary>
        /// Try and derive the requested number of bytes for the specified key, writing to the provided buffer.
        /// </summary>
        /// <param name="buffer">The output buffer.</param>
        /// <param name="key">The exchange key to derive.</param>
        /// <returns>If the derivation was successful.</returns>
        public bool TryDeriveBytes(Span<byte> buffer, ExchangeKey key)
        {
            // Get the character that seasons the key input hash, see RFC4253 7.2
            char keyChar = GetKeyCharacter(key);
            
            // Copy everything into a stack allocated buffer ready to hash
            int sharedSecretByteCount = MpInteger.GetByteCount(SharedSecret);
            int offset = 0;
            Span<byte> seedBuffer = stackalloc byte[sharedSecretByteCount
                                                   + ExchangeHash.Length
                                                   + 1
                                                   + SessionId.Length];

            MpInteger.TryWriteBytes(SharedSecret, seedBuffer.Slice(offset, sharedSecretByteCount), out _);
            offset += sharedSecretByteCount;
            
            ExchangeHash.Span.CopyTo(seedBuffer.Slice(offset, ExchangeHash.Length));
            offset += ExchangeHash.Length;

            seedBuffer[offset] = (byte) keyChar; // Seasoning
            offset++;
            
            SessionId.Span.CopyTo(seedBuffer.Slice(offset, SessionId.Length));

            // Produce the hash: HASH(Secret || ExchangeHash || KeyChar || SessionId)
            Span<byte> hashBuffer = stackalloc byte[_hashAlg.HashSize];

            if (!_hashAlg.TryComputeHash(seedBuffer, hashBuffer, out _)) {
                throw new CryptographicException("The key derivation hash could not be computed");
            }
            
            // Copy as many of the initial hash bytes to the output buffer as possible
            // If we have enough bytes to fulfill the request we can stop here
            hashBuffer.Slice(0, buffer.Length).CopyTo(buffer);
            
            if (buffer.Length <= hashBuffer.Length) {
                return true;
            }
            
            // We didn't have enough bytes so we need to keep concatenating and producing more
            //
            // We can reuse the seedBuffer allocation, as we always try and hash less data than the first hash
            // The concat hash is HASH(Secret || ExchangeHash [|| PreviousKey]+)
            //TODO: This needs finishing
            int remainingBytes = buffer.Length - hashBuffer.Length;
            throw new NotImplementedException();
        }
        
        /// <summary>
        /// The exchange hash (H) from the key exchange.
        /// </summary>
        public ReadOnlyMemory<byte> ExchangeHash { get; }
        
        /// <summary>
        /// The session ID, which is the first exchange hash (H) for this connection.
        /// </summary>
        public ReadOnlyMemory<byte> SessionId { get; }
        
        /// <summary>
        /// The shared secret produced by the key exchange.
        /// </summary>
        public BigInteger SharedSecret { get; }

        public ExchangeOutput(ReadOnlyMemory<byte> exchangeHash, ReadOnlyMemory<byte> sessionId,
            BigInteger sharedSecret, HashAlgorithm hashAlgorithm)
        {
            ExchangeHash = exchangeHash;
            SessionId = sessionId;
            SharedSecret = sharedSecret;
            _hashAlg = hashAlgorithm;
        }
    }
}