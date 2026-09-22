using System.Security.Cryptography;
using HkdfGuard.Abstractions;
using HkdfGuard.CryptoSession.AesGcm256;
using HkdfGuard.DataEncryptionKey;

namespace HkdfGuard.DataEncryptionKey.Test;

public class PipelineDataEncryptionKeyTests
{
    private static readonly Func<IKeyWrapper, byte[], ICryptoProvider> SessionProviderFactory =
        (keyWrapper, wrapped) => new AesGcmCryptoProvider(keyWrapper, wrapped, 60);

    [Fact]
    public void Constructor_WithNoDekSupplied_GeneratesARandom32ByteDek()
    {
        using var key = new PipelineDataEncryptionKey(SessionProviderFactory);

        Assert.Equal(32, key.AsSpan().Length);
        Assert.False(key.AsSpan().ToArray().All(b => b == 0));
    }

    [Fact]
    public void Constructor_WithNoDekSupplied_GeneratesADifferentDekEachTime()
    {
        using var key1 = new PipelineDataEncryptionKey(SessionProviderFactory);
        using var key2 = new PipelineDataEncryptionKey(SessionProviderFactory);

        Assert.NotEqual(key1.AsSpan().ToArray(), key2.AsSpan().ToArray());
    }

    [Fact]
    public void Constructor_WithSuppliedDek_UsesItAsIs()
    {
        var dek = RandomNumberGenerator.GetBytes(32);
        var expected = (byte[])dek.Clone();

        using var key = new PipelineDataEncryptionKey(dek, SessionProviderFactory);

        Assert.Equal(expected, key.AsSpan().ToArray());
    }

    [Fact]
    public void Constructor_WithEmptyDek_Throws()
    {
        Assert.Throws<ArgumentException>(() => new PipelineDataEncryptionKey(new byte[32], SessionProviderFactory));
    }

    [Fact]
    public void Constructor_WithWrongSizeDek_Throws()
    {
        Assert.Throws<ArgumentException>(() => new PipelineDataEncryptionKey(RandomNumberGenerator.GetBytes(16), SessionProviderFactory));
    }

    [Fact]
    public void EncryptDecrypt_RoundTrips()
    {
        using var key = new PipelineDataEncryptionKey(SessionProviderFactory);
        var plaintext = "top secret"u8.ToArray();
        var expected = (byte[])plaintext.Clone();

        var encrypted = key.Encrypt(plaintext);
        var decrypted = new byte[expected.Length];
        var written = key.Decrypt(encrypted, decrypted);

        Assert.Equal(expected.Length, written);
        Assert.Equal(expected, decrypted);
    }

    [Fact]
    public void EncryptDecrypt_WithAad_RoundTrips()
    {
        using var key = new PipelineDataEncryptionKey(SessionProviderFactory);
        var plaintext = "top secret"u8.ToArray();
        var expected = (byte[])plaintext.Clone();
        var aad = "context"u8.ToArray();

        var encrypted = key.Encrypt(plaintext, aad);
        var decrypted = new byte[expected.Length];
        var written = key.Decrypt(encrypted, aad, decrypted);

        Assert.Equal(expected, decrypted[..written]);
    }

    [Fact]
    public void Decrypt_WithMismatchedAad_Throws()
    {
        using var key = new PipelineDataEncryptionKey(SessionProviderFactory);
        var encrypted = key.Encrypt("top secret"u8.ToArray(), "context-a"u8.ToArray());

        Assert.Throws<AuthenticationTagMismatchException>(() =>
            key.Decrypt(encrypted, "context-b"u8.ToArray(), new byte[16]));
    }

    [Fact]
    public void TwoInstances_WithDifferentGeneratedDeks_CannotDecryptEachOthersCiphertext()
    {
        using var key1 = new PipelineDataEncryptionKey(SessionProviderFactory);
        using var key2 = new PipelineDataEncryptionKey(SessionProviderFactory);

        var encrypted = key1.Encrypt("top secret"u8.ToArray());

        Assert.ThrowsAny<CryptographicException>(() => key2.Decrypt(encrypted, new byte[16]));
    }

    [Fact]
    public void Dispose_ZeroesTheDek()
    {
        var key = new PipelineDataEncryptionKey(SessionProviderFactory);

        key.Dispose();

        Assert.Equal(new byte[32], key.AsSpan().ToArray());
    }
}
