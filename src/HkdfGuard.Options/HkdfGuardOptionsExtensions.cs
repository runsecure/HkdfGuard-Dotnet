using HkdfGuard.DataEncryptionKey;

namespace HkdfGuard.Options;

/// <summary>
/// Copies a validated HkdfGuardOptions instance onto a KeyRingBuilder - ServiceName,
/// CachedKeyExpiry, KeyRotationDays, every registered KeyFile, and every registered
/// EphemeralKey. The caller still supplies WithKeyWrapper/WithSessionProviderFactory/
/// WithFormatProvider and calls Build() themselves - those are behavior, not something
/// HkdfGuardOptions can carry as data.
/// </summary>
public static class HkdfGuardOptionsExtensions
{
    public static KeyRingBuilder ApplyTo(this HkdfGuardOptions options, KeyRingBuilder builder)
    {
        if (options.ServiceName is not null)
            builder.WithServiceName(options.ServiceName);

        if (options.CachedKeyExpiry is { } cachedKeyExpiry)
            builder.WithCachedKeyExpiry(cachedKeyExpiry);

        if (options.KeyRotationDays is { } keyRotationDays)
            builder.WithKeyRotationDays(keyRotationDays);

        foreach (var keyFile in options.KeyFiles)
            builder.WithKeyFile(keyFile.Version, keyFile.Path);

        foreach (var version in options.EphemeralKeys)
            builder.WithEphemeralKey(version);

        return builder;
    }
}
