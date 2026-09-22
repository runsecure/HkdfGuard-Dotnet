using System.Security.Cryptography;
using HkdfGuard.Abstractions;
using HkdfGuard.CryptoSession.AesGcm256;
using HkdfGuard.DataEncryptionKey;
using HkdfGuard.DataEncryptionKey.Test.TestHelpers;

namespace HkdfGuard.DataEncryptionKey.Test;

public class KeyWrappedDataEncryptionKeyTests
{
    private static KeyWrappedDataEncryptionKey CreateKey(out FakeKeyWrapper wrapper)
    {
        wrapper = new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32));
        return new KeyWrappedDataEncryptionKey(new AesGcmCryptoSessionProvider(wrapper, "wrapped"u8.ToArray(), 60));
    }

    [Fact]
    public void EncryptDecrypt_RoundTrips()
    {
        var dataProtectionKey = CreateKey(out _);
        var plaintext = "top secret"u8.ToArray();
        // AesGcmCryptoSession.Encrypt zeroes the plaintext span it's given as a side effect.
        var expected = (byte[])plaintext.Clone();

        var encrypted = dataProtectionKey.Encrypt(plaintext);
        Assert.Equal(expected.Length + 12 + 16, encrypted.Length);

        var decrypted = new byte[expected.Length];
        var decryptedLength = dataProtectionKey.Decrypt(encrypted, decrypted);

        Assert.Equal(expected.Length, decryptedLength);
        Assert.Equal(expected, decrypted);
    }

    [Fact]
    public void EncryptDecrypt_WithAad_RoundTrips()
    {
        var dataProtectionKey = CreateKey(out _);
        var plaintext = "top secret"u8.ToArray();
        var expected = (byte[])plaintext.Clone();
        var aad = "context"u8.ToArray();

        var encrypted = dataProtectionKey.Encrypt(plaintext, aad);

        var decrypted = new byte[expected.Length];
        var decryptedLength = dataProtectionKey.Decrypt(encrypted, aad, decrypted);

        Assert.Equal(expected, decrypted[..decryptedLength]);
    }

    [Fact]
    public void Decrypt_WithMismatchedAad_Throws()
    {
        var dataProtectionKey = CreateKey(out _);
        var plaintext = "top secret"u8.ToArray();
        var encrypted = dataProtectionKey.Encrypt(plaintext, "context-a"u8.ToArray());

        var result = new byte[plaintext.Length];
        Assert.Throws<AuthenticationTagMismatchException>(() =>
            dataProtectionKey.Decrypt(encrypted, "context-b"u8.ToArray(), result));
    }

    [Fact]
    public void EncryptDecrypt_WithSensitiveLoggingEnabled_StillRoundTrips()
    {
        using var loggingScope = new SensitiveLoggingScope(true);

        var dataProtectionKey = CreateKey(out _);
        var plaintext = "top secret"u8.ToArray();
        var expected = (byte[])plaintext.Clone();

        var encrypted = dataProtectionKey.Encrypt(plaintext);
        var decrypted = new byte[expected.Length];
        var decryptedLength = dataProtectionKey.Decrypt(encrypted, decrypted);

        Assert.Equal(expected, decrypted[..decryptedLength]);
    }

    [Fact]
    public void Encrypt_ReturnsExactlySizedArray()
    {
        var dataProtectionKey = CreateKey(out _);
        var plaintext = "a longer plaintext value to encrypt"u8.ToArray();
        var expectedLength = plaintext.Length + 12 + 16; // AES-GCM nonce + tag overhead

        var encrypted = dataProtectionKey.Encrypt(plaintext);

        Assert.Equal(expectedLength, encrypted.Length);
    }

    [Fact]
    public void Encrypt_WhenSessionProviderFails_RecordsExceptionAndThrows()
    {
        var dataProtectionKey = new KeyWrappedDataEncryptionKey(
            new ThrowingCryptoSessionProvider(new InvalidOperationException("session unavailable")));

        Assert.Throws<InvalidOperationException>(() => dataProtectionKey.Encrypt("top secret"u8.ToArray()));
    }

    [Fact]
    public void Decrypt_WhenSessionProviderFails_RecordsExceptionAndThrows()
    {
        var dataProtectionKey = new KeyWrappedDataEncryptionKey(
            new ThrowingCryptoSessionProvider(new InvalidOperationException("session unavailable")));

        Assert.Throws<InvalidOperationException>(() => dataProtectionKey.Decrypt(ReadOnlySpan<byte>.Empty, new byte[16]));
    }

    [Fact]
    public void EncryptAndDecrypt_ReuseTheCachedSessionAcrossCalls()
    {
        // AesGcmCryptoSessionProvider only calls back into the key wrapper when it has no cached
        // session yet or the cached one has expired - not on every operation - so a wrapper's
        // key is revealed once here, then reused for every subsequent Encrypt/Decrypt.
        var dataProtectionKey = CreateKey(out var wrapper);
        var encrypted1 = dataProtectionKey.Encrypt("one"u8.ToArray());
        var encrypted2 = dataProtectionKey.Encrypt("two"u8.ToArray());

        dataProtectionKey.Decrypt(encrypted1, new byte[3]);
        dataProtectionKey.Decrypt(encrypted2, new byte[3]);

        Assert.Equal(1, wrapper.DecryptCallCount);
    }
}
