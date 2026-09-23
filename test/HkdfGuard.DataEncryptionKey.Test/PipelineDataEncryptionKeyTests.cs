using System.Security.Cryptography;
using HkdfGuard.Abstractions;
using HkdfGuard.CryptoSession.AesGcm256;

namespace HkdfGuard.DataEncryptionKey.Test;

public class PipelineDataEncryptionKeyTests
{
    private static readonly ICryptoProviderFactory CryptoProviderFactory = new AesGcmCryptoProviderFactory();

    private static PipelineDataEncryptionKey CreateKey(byte[]? dek = null)
    {
        dek ??= RandomNumberGenerator.GetBytes(32);
        var provider = CryptoProviderFactory.CreateForPipeline(new DummyKeyWrapper(), dek);
        return new PipelineDataEncryptionKey(provider, dek);
    }

    [Fact]
    public void AsSpan_ReturnsTheSuppliedDek()
    {
        var dek = RandomNumberGenerator.GetBytes(32);
        var expected = (byte[])dek.Clone();
        var key = CreateKey(dek);

        Assert.Equal(expected, key.AsSpan().ToArray());
    }

    [Fact]
    public void EncryptDecrypt_RoundTrips()
    {
        var key = CreateKey();
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
        var key = CreateKey();
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
        var key = CreateKey();
        var encrypted = key.Encrypt("top secret"u8.ToArray(), "context-a"u8.ToArray());

        Assert.Throws<AuthenticationTagMismatchException>(() =>
            key.Decrypt(encrypted, "context-b"u8.ToArray(), new byte[16]));
    }

    [Fact]
    public void TwoInstances_WithDifferentDeks_CannotDecryptEachOthersCiphertext()
    {
        var key1 = CreateKey();
        var key2 = CreateKey();

        var encrypted = key1.Encrypt("top secret"u8.ToArray());

        Assert.ThrowsAny<CryptographicException>(() => key2.Decrypt(encrypted, new byte[16]));
    }

    [Fact]
    public void Dispose_ZeroesTheDek()
    {
        var dek = RandomNumberGenerator.GetBytes(32);
        var key = CreateKey(dek);

        key.Dispose();

        Assert.Equal(new byte[32], dek);
    }

    [Fact]
    public void Dispose_DoesNotThrow()
    {
        // Regression test: AesGcmCryptoProvider's pipeline-only constructor used to leave its
        // background-refresh task field null, which crashed Dispose with a
        // NullReferenceException once PipelineDataEncryptionKey started disposing its provider.
        var key = CreateKey();

        var ex = Record.Exception(key.Dispose);

        Assert.Null(ex);
    }
}
