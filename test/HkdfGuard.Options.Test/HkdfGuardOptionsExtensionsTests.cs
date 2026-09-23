using System.Security.Cryptography;
using HkdfGuard.CryptoSession.AesGcm256;
using HkdfGuard.DataEncryptionKey;
using HkdfGuard.Options.Test.TestHelpers;

namespace HkdfGuard.Options.Test;

public class HkdfGuardOptionsExtensionsTests
{
    [Fact]
    public void ApplyTo_ReturnsSameBuilderForChaining()
    {
        var builder = new KeyRingBuilder();
        var options = new HkdfGuardOptions();

        var returned = options.ApplyTo(builder);

        Assert.Same(builder, returned);
    }

    [Fact]
    public void ApplyTo_SetsServiceNameCachedKeyExpiryAndKeyRotationDays()
    {
        var options = new HkdfGuardOptions
        {
            ServiceName = "my-service",
            CachedKeyExpiry = 60,
            KeyRotationDays = 90,
        };

        var builder = options.ApplyTo(new KeyRingBuilder());

        Assert.Equal("my-service", builder.ServiceName);
        Assert.Equal(60, builder.CachedKeyExpiry);
        Assert.Equal(90, builder.KeyRotationDays);
    }

    [Fact]
    public void ApplyTo_UnsetFields_LeavesBuilderDefaultsUntouched()
    {
        var builder = new HkdfGuardOptions().ApplyTo(new KeyRingBuilder());

        Assert.Null(builder.ServiceName);
        Assert.Null(builder.CachedKeyExpiry);
        Assert.Null(builder.KeyRotationDays);
    }

    [Fact]
    public void ApplyTo_WithEphemeralKeys_RegistersEachOnBuild()
    {
        var options = new HkdfGuardOptions { EphemeralKeys = [1, 2] };

        var ring = options.ApplyTo(new KeyRingBuilder())
            .WithKeyWrapper(new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)))
            .WithCryptoProviderFactory(new AesGcmCryptoProviderFactory())
            .WithCachedKeyExpiry(60)
            .Build();

        Assert.Equal(2, ring.CurrentVersion);
    }

    [Fact]
    public void ApplyTo_WithKeyFiles_RegistersEachOnBuild()
    {
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, "wrapped"u8.ToArray());
            var options = new HkdfGuardOptions
            {
                KeyFiles = [new KeyFileOptions { Version = 1, Path = path }],
            };

            var ring = options.ApplyTo(new KeyRingBuilder())
                .WithKeyWrapper(new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)))
                .WithCryptoProviderFactory(new AesGcmCryptoProviderFactory())
                .WithCachedKeyExpiry(60)
                .Build();

            Assert.Equal(1, ring.CurrentVersion);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void ApplyTo_WithKeyFilesAndEphemeralKeys_HighestVersionBecomesCurrent()
    {
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, "wrapped"u8.ToArray());
            var options = new HkdfGuardOptions
            {
                KeyFiles = [new KeyFileOptions { Version = 1, Path = path }],
                EphemeralKeys = [2],
            };

            var ring = options.ApplyTo(new KeyRingBuilder())
                .WithKeyWrapper(new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)))
                .WithCryptoProviderFactory(new AesGcmCryptoProviderFactory())
                .WithCachedKeyExpiry(60)
                .Build();

            Assert.Equal(2, ring.CurrentVersion);
        }
        finally
        {
            File.Delete(path);
        }
    }
}
