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
        NewKeys = 21,

        UserAuthRequest = 50,
        UserAuthFailure = 51,
        UserAuthSuccess = 52,
        UserAuthBanner = 53,
        GlobalRequest = 80,
        RequestSuccess = 81,
        RequestFailure = 82,
        ChannelOpen = 90,
        ChannelOpenConfirmation = 91,
        ChannelOpenFailure = 92,
        ChannelWindowAdjust = 93,
        ChannelData = 93,
        ChannelExtendedData = 95,
        ChannelEof = 96,
        ChannelClose = 97,
        ChannelRequest = 98,
        ChannelSuccess = 99,
        ChannelFailure = 100
    }
}