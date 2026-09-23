using HkdfGuard.DataEncryptionKey;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace HkdfGuard.DependencyInjection;

/// <summary>
/// Registers a KeyRing into an IServiceCollection.
/// </summary>
public static class HkdfGuardServiceCollectionExtensions
{
    /// <summary>
    /// Registers a KeyRing as a singleton, built lazily on first resolution by handing a fresh
    /// KeyRingBuilder to configure - e.g.
    /// <c>services.AddKeyRing(builder => builder.WithServiceName("my-service")
    ///     .WithKeyWrapper(new NativeHkdfKeyWrapperV1("my-service"))
    ///     .WithCryptoProviderFactory((kw, wrapped) => new AesGcmCryptoSessionProvider(kw, wrapped, 60))
    ///     .WithKeyFile(1, "/path/to/wrapped-dek-v1.bin")
    ///     .Build())</c>.
    /// A second call is a no-op - only the first registered KeyRing wins, the same as every other
    /// TryAddSingleton in this ecosystem.
    /// </summary>
    public static IServiceCollection AddKeyRing(this IServiceCollection services, Func<KeyRingBuilder, KeyRing> configure)
    {
        services.TryAddSingleton(_ => configure(new KeyRingBuilder()));
        return services;
    }
}
