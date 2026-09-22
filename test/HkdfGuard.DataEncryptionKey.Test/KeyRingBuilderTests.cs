using System.Security.Cryptography;
using HkdfGuard.Abstractions;
using HkdfGuard.CryptoSession.AesGcm256;
using HkdfGuard.DataEncryptionKey.Test.TestHelpers;

namespace HkdfGuard.DataEncryptionKey.Test;

public class KeyRingBuilderTests
{
    private static readonly Func<IKeyWrapper, byte[], ICryptoProvider> SessionProviderFactory =
        (keyWrapper, wrapped) => new AesGcmCryptoProvider(keyWrapper, wrapped, 60);

    [Fact]
    public void WithServiceName_SetsServiceName()
    {
        var builder = new KeyRingBuilder().WithServiceName("my-service");

        Assert.Equal("my-service", builder.ServiceName);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(300)]
    public void WithCachedKeyExpiry_WithinRange_SetsCachedKeyExpiry(int cachedKeyExpiry)
    {
        var builder = new KeyRingBuilder().WithCachedKeyExpiry(cachedKeyExpiry);

        Assert.Equal(cachedKeyExpiry, builder.CachedKeyExpiry);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(301)]
    public void WithCachedKeyExpiry_OutOfRange_Throws(int cachedKeyExpiry)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new KeyRingBuilder().WithCachedKeyExpiry(cachedKeyExpiry));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(180)]
    public void WithKeyRotationDays_WithinRange_SetsKeyRotationDays(int keyRotationDays)
    {
        var builder = new KeyRingBuilder().WithKeyRotationDays(keyRotationDays);

        Assert.Equal(keyRotationDays, builder.KeyRotationDays);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(181)]
    public void WithKeyRotationDays_OutOfRange_Throws(int keyRotationDays)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new KeyRingBuilder().WithKeyRotationDays(keyRotationDays));
    }

    [Fact]
    public void Build_WithoutKeyWrapper_Throws()
    {
        var builder = new KeyRingBuilder()
            .WithSessionProviderFactory(SessionProviderFactory)
            .WithEphemeralKey(1);

        Assert.Throws<InvalidOperationException>(() => builder.Build());
    }

    [Fact]
    public void Build_WithoutSessionProviderFactory_Throws()
    {
        var builder = new KeyRingBuilder()
            .WithKeyWrapper(new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)))
            .WithEphemeralKey(1);

        Assert.Throws<InvalidOperationException>(() => builder.Build());
    }

    [Fact]
    public void Build_WithoutKeyFilesOrEphemeralKeys_Throws()
    {
        var builder = new KeyRingBuilder()
            .WithKeyWrapper(new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)))
            .WithSessionProviderFactory(SessionProviderFactory);

        Assert.Throws<InvalidOperationException>(() => builder.Build());
    }

    [Fact]
    public void Build_WithKeyFile_RegistersVersionFromFile()
    {
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, "wrapped"u8.ToArray());

            var ring = new KeyRingBuilder()
                .WithKeyWrapper(new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)))
                .WithSessionProviderFactory(SessionProviderFactory)
                .WithKeyFile(1, path)
                .Build();

            Assert.Equal(1, ring.CurrentVersion);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Build_WithMultipleKeyFiles_HighestVersionBecomesCurrent()
    {
        var path1 = Path.GetTempFileName();
        var path2 = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path1, "wrapped-v1"u8.ToArray());
            File.WriteAllBytes(path2, "wrapped-v2"u8.ToArray());

            var ring = new KeyRingBuilder()
                .WithKeyWrapper(new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)))
                .WithSessionProviderFactory(SessionProviderFactory)
                .WithKeyFile(1, path1)
                .WithKeyFile(2, path2)
                .Build();

            Assert.Equal(2, ring.CurrentVersion);
        }
        finally
        {
            File.Delete(path1);
            File.Delete(path2);
        }
    }

    [Fact]
    public void Build_WithEphemeralKey_RegistersVersion()
    {
        var ring = new KeyRingBuilder()
            .WithKeyWrapper(new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)))
            .WithSessionProviderFactory(SessionProviderFactory)
            .WithEphemeralKey(1)
            .Build();

        Assert.Equal(1, ring.CurrentVersion);
    }

    [Fact]
    public void Build_WithEphemeralKey_ProducesAWorkingKey()
    {
        var ring = new KeyRingBuilder()
            .WithKeyWrapper(new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)))
            .WithSessionProviderFactory(SessionProviderFactory)
            .WithEphemeralKey(1)
            .Build();

        var key = ring.Get(1);
        var plaintext = "top secret"u8.ToArray();
        var expected = (byte[])plaintext.Clone();

        var encrypted = key.Encrypt(plaintext);
        var decrypted = new byte[expected.Length];
        var written = key.Decrypt(encrypted, decrypted);

        Assert.Equal(expected.Length, written);
        Assert.Equal(expected, decrypted);
    }

    [Fact]
    public void Build_WithKeyFileAndHigherVersionEphemeralKey_EphemeralBecomesCurrent()
    {
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, "wrapped"u8.ToArray());

            var ring = new KeyRingBuilder()
                .WithKeyWrapper(new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)))
                .WithSessionProviderFactory(SessionProviderFactory)
                .WithKeyFile(1, path)
                .WithEphemeralKey(2)
                .Build();

            Assert.Equal(2, ring.CurrentVersion);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Build_UsesConfiguredFormatProvider()
    {
        var recordingFormatProvider = new RecordingFormatProvider();

        var ring = new KeyRingBuilder()
            .WithKeyWrapper(new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32)))
            .WithSessionProviderFactory(SessionProviderFactory)
            .WithEphemeralKey(1)
            .WithFormatProvider(recordingFormatProvider)
            .Build();

        ring.CreateProtector("purpose").Encrypt("hello".AsSpan());

        Assert.True(recordingFormatProvider.FormatCalled);
    }
}
