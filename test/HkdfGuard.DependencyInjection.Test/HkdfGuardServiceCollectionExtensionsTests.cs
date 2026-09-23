using System.Security.Cryptography;
using HkdfGuard.CryptoSession.AesGcm256;
using HkdfGuard.DataEncryptionKey;
using HkdfGuard.DependencyInjection.Test.TestHelpers;
using Microsoft.Extensions.DependencyInjection;

namespace HkdfGuard.DependencyInjection.Test;

public class HkdfGuardServiceCollectionExtensionsTests
{
    private static KeyRing BuildRing(KeyRingBuilder builder)
        => builder
            .WithKeyWrapper(new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)))
            .WithCryptoProviderFactory(new AesGcmCryptoProviderFactory())
            .WithCachedKeyExpiry(60)
            .WithEphemeralKey(1)
            .Build();

    [Fact]
    public void AddKeyRing_ReturnsTheSameServiceCollectionForChaining()
    {
        var services = new ServiceCollection();

        var returned = services.AddKeyRing(BuildRing);

        Assert.Same(services, returned);
    }

    [Fact]
    public void AddKeyRing_DoesNotInvokeConfigureUntilFirstResolution()
    {
        var invoked = false;
        var services = new ServiceCollection();
        services.AddKeyRing(builder =>
        {
            invoked = true;
            return BuildRing(builder);
        });

        using var provider = services.BuildServiceProvider();
        Assert.False(invoked);

        _ = provider.GetRequiredService<KeyRing>();
        Assert.True(invoked);
    }

    [Fact]
    public void AddKeyRing_RegistersKeyRingAsASingleton()
    {
        var services = new ServiceCollection();
        services.AddKeyRing(BuildRing);

        using var provider = services.BuildServiceProvider();
        var ring1 = provider.GetRequiredService<KeyRing>();
        var ring2 = provider.GetRequiredService<KeyRing>();

        Assert.Same(ring1, ring2);
    }

    [Fact]
    public void AddKeyRing_ResolvesAWorkingKeyRing()
    {
        var services = new ServiceCollection();
        services.AddKeyRing(BuildRing);

        using var provider = services.BuildServiceProvider();
        var ring = provider.GetRequiredService<KeyRing>();

        var protector = ring.CreateProtector("cookie-auth");
        var formatted = protector.Encrypt("hello".AsSpan());
        Span<char> result = new char[protector.GetMaxDecryptedLength(formatted.AsSpan())];
        var written = protector.Decrypt(formatted.AsSpan(), result);

        Assert.Equal("hello", new string(result[..written]));
    }

    [Fact]
    public void AddKeyRing_CalledTwice_KeepsTheFirstRegistration()
    {
        var services = new ServiceCollection();
        services.AddKeyRing(BuildRing);
        services.AddKeyRing(builder => builder
            .WithKeyWrapper(new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)))
            .WithCryptoProviderFactory(new AesGcmCryptoProviderFactory())
            .WithCachedKeyExpiry(60)
            .WithEphemeralKey(2)
            .Build());

        using var provider = services.BuildServiceProvider();
        var ring = provider.GetRequiredService<KeyRing>();

        Assert.Equal(1, ring.CurrentVersion);
    }
}
