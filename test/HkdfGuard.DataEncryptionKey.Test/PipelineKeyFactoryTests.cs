using System.Globalization;
using HkdfGuard.Abstractions;
using HkdfGuard.CryptoSession.AesGcm256;

namespace HkdfGuard.DataEncryptionKey.Test;

public class PipelineKeyFactoryTests
{
    private static readonly ICryptoProviderFactory CryptoProviderFactory = new AesGcmCryptoProviderFactory();

    [Fact]
    public void Create_GeneratesA32ByteDek()
    {
        var factory = new PipelineKeyFactory();

        using var key = factory.Create(CryptoProviderFactory, CultureInfo.InvariantCulture);

        Assert.Equal(32, key.AsSpan().Length);
        Assert.False(key.AsSpan().ToArray().All(b => b == 0));
    }

    [Fact]
    public void Create_GeneratesADifferentDekEachTime()
    {
        var factory = new PipelineKeyFactory();

        using var key1 = factory.Create(CryptoProviderFactory, CultureInfo.InvariantCulture);
        using var key2 = factory.Create(CryptoProviderFactory, CultureInfo.InvariantCulture);

        Assert.NotEqual(key1.AsSpan().ToArray(), key2.AsSpan().ToArray());
    }

    [Fact]
    public void Create_ProducesAWorkingKey()
    {
        var factory = new PipelineKeyFactory();
        using var key = factory.Create(CryptoProviderFactory, CultureInfo.InvariantCulture);
        var plaintext = "top secret"u8.ToArray();
        var expected = (byte[])plaintext.Clone();

        var encrypted = key.Encrypt(plaintext);
        var decrypted = new byte[expected.Length];
        var written = key.Decrypt(encrypted, decrypted);

        Assert.Equal(expected.Length, written);
        Assert.Equal(expected, decrypted);
    }

    [Fact]
    public void Create_KeyCanBeDisposedWithoutThrowing()
    {
        var factory = new PipelineKeyFactory();
        var key = factory.Create(CryptoProviderFactory, CultureInfo.InvariantCulture);

        var ex = Record.Exception(key.Dispose);

        Assert.Null(ex);
    }
}
