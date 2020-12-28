namespace SecureShell.Protocol
{
    /// <summary>
    /// Defines the known message numbers.
    /// </summary>
    public enum MessageNumber
    {
        /// <summary>
        /// A disconnect request.
        /// </summary>
        Disconnect = 1,

        /// <summary>
        /// Ignore, used for debugging or to add dummy packets for cryptographic purposes.
        /// </summary>
        Ignore = 2,

        /// <summary>
        /// Sent for misunderstood messages.
        /// </summary>
        Unimplemented = 3,

        /// <summary>
        /// Debug message to potentially be shown to user.
        /// </summary>
        Debug = 4,

        /// <summary>
        /// Service request.
        /// </summary>
        ServiceRequest = 5,

        /// <summary>
        /// Service acceptance result.
        /// </summary>
        ServiceAccept = 6,

        /// <summary>
        /// Initialization of key exchange.
        /// </summary>
        KeyInitialization = 20,

        /// <summary>
        /// New keys to be used onward.
        /// </summary>
        NewKeys = 21
    }
}