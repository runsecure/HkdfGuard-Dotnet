using System.Security.Cryptography;
using HkdfGuard.CryptoSession.AesGcm256;

namespace HkdfGuard.CryptoSession.AesGcm256.Test;

public class AesGcmCryptoSessionTests
{
    [Fact]
    public void EncryptDecrypt_RoundTrips()
    {
        using var cipher = new AesGcmCryptoSession(RandomNumberGenerator.GetBytes(32), 60);
        var plaintext = "hello world"u8.ToArray();
        var expectedPlaintext = (byte[])plaintext.Clone();
        var encrypted = new byte[plaintext.Length + 28];

        var written = cipher.Encrypt(plaintext, encrypted);
        Assert.Equal(encrypted.Length, written);

        var decrypted = new byte[expectedPlaintext.Length];
        var decryptedLength = cipher.Decrypt(encrypted, decrypted);

        Assert.Equal(expectedPlaintext.Length, decryptedLength);
        Assert.Equal(expectedPlaintext, decrypted);
    }

    [Fact]
    public void EncryptDecrypt_RoundTrips_WithAad()
    {
        using var cipher = new AesGcmCryptoSession(RandomNumberGenerator.GetBytes(32), 60);
        var plaintext = "hello world"u8.ToArray();
        var expectedPlaintext = (byte[])plaintext.Clone();
        var aad = "context"u8.ToArray();
        var encrypted = new byte[plaintext.Length + 28];

        cipher.Encrypt(plaintext, aad, encrypted);

        var decrypted = new byte[expectedPlaintext.Length];
        cipher.Decrypt(encrypted, aad, decrypted);

        Assert.Equal(expectedPlaintext, decrypted);
    }

    [Fact]
    public void Decrypt_WithWrongAad_Throws()
    {
        using var cipher = new AesGcmCryptoSession(RandomNumberGenerator.GetBytes(32), 60);
        var plaintext = "hello world"u8.ToArray();
        var encrypted = new byte[plaintext.Length + 28];
        cipher.Encrypt(plaintext, "correct-aad"u8.ToArray(), encrypted);

        var decrypted = new byte[11];
        Assert.Throws<AuthenticationTagMismatchException>(() =>
            cipher.Decrypt(encrypted, "wrong-aad"u8.ToArray(), decrypted));
    }

    [Fact]
    public void Decrypt_WithTamperedCiphertext_Throws()
    {
        using var cipher = new AesGcmCryptoSession(RandomNumberGenerator.GetBytes(32), 60);
        var plaintext = "hello world"u8.ToArray();
        var encrypted = new byte[plaintext.Length + 28];
        cipher.Encrypt(plaintext, encrypted);
        encrypted[15] ^= 0xFF;

        var decrypted = new byte[11];
        Assert.Throws<AuthenticationTagMismatchException>(() => cipher.Decrypt(encrypted, decrypted));
    }

    [Fact]
    public void Encrypt_WithTooSmallResultBuffer_Throws()
    {
        using var cipher = new AesGcmCryptoSession(RandomNumberGenerator.GetBytes(32), 60);
        var plaintext = "hello world"u8.ToArray();
        var tooSmall = new byte[plaintext.Length];

        Assert.Throws<ArgumentException>(() => cipher.Encrypt(plaintext, tooSmall));
    }

    [Fact]
    public void Decrypt_WithTooShortCiphertext_Throws()
    {
        using var cipher = new AesGcmCryptoSession(RandomNumberGenerator.GetBytes(32), 60);
        var tooShort = new byte[10];
        var result = new byte[4];

        Assert.Throws<ArgumentException>(() => cipher.Decrypt(tooShort, result));
    }

    [Fact]
    public void Constructor_WithInvalidKeySize_Throws()
    {
        var invalidKey = RandomNumberGenerator.GetBytes(10);

        Assert.Throws<ArgumentException>(() => new AesGcmCryptoSession(invalidKey, 60));
    }

    [Fact]
    public void Constructor_WithAllZeroKey_Throws()
    {
        var zeroKey = new byte[32];

        Assert.Throws<ArgumentException>(() => new AesGcmCryptoSession(zeroKey, 60));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(301)]
    public void Constructor_DoesNotValidateExpirySeconds(int expirySeconds)
    {
        // AesGcmCryptoSession is internal - its only caller, AesGcmCryptoSessionProvider, already
        // validates expirySeconds (see AesGcmCryptoSessionProviderTests), so this constructor
        // trusts it rather than re-checking.
        using var session = new AesGcmCryptoSession(RandomNumberGenerator.GetBytes(32), expirySeconds);
    }

    [Fact]
    public void Constructor_SetsExpiresAtApproximatelyExpirySecondsFromNow()
    {
        var before = DateTimeOffset.UtcNow;
        using var cipher = new AesGcmCryptoSession(RandomNumberGenerator.GetBytes(32), 60);
        var after = DateTimeOffset.UtcNow;

        Assert.InRange(cipher.ExpiresAt, before.AddSeconds(60), after.AddSeconds(60));
    }

    [Fact]
    public void Encrypt_WithAllZeroPlaintext_Throws()
    {
        using var cipher = new AesGcmCryptoSession(RandomNumberGenerator.GetBytes(32), 60);
        var zeroPlaintext = new byte[11];
        var encrypted = new byte[zeroPlaintext.Length + 28];

        Assert.Throws<ArgumentException>(() => cipher.Encrypt(zeroPlaintext, encrypted));
    }

    [Fact]
    public void Decrypt_WithNonZeroButTooShortCiphertext_Throws()
    {
        using var cipher = new AesGcmCryptoSession(RandomNumberGenerator.GetBytes(32), 60);
        var tooShort = RandomNumberGenerator.GetBytes(10); // non-zero, but shorter than nonce + tag
        var result = new byte[4];

        Assert.Throws<ArgumentException>(() => cipher.Decrypt(tooShort, result));
    }

    [Fact]
    public void Decrypt_WithTooSmallResultBuffer_Throws()
    {
        using var cipher = new AesGcmCryptoSession(RandomNumberGenerator.GetBytes(32), 60);
        var plaintext = "hello world"u8.ToArray();
        var encrypted = new byte[plaintext.Length + 28];
        cipher.Encrypt(plaintext, encrypted);

        var tooSmall = new byte[plaintext.Length - 1];
        Assert.Throws<ArgumentException>(() => cipher.Decrypt(encrypted, tooSmall));
    }

    [Fact]
    public void Dispose_ZeroesTheKey()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var keyClone = (byte[])key.Clone();
        var cipher = new AesGcmCryptoSession(key, 60);

        cipher.Dispose();

        Assert.Equal(new byte[32], key);
        Assert.NotEqual(keyClone, key);
    }

    [Fact]
    public void Dispose_ThenEncrypt_Throws()
    {
        var cipher = new AesGcmCryptoSession(RandomNumberGenerator.GetBytes(32), 60);
        cipher.Dispose();

        Assert.Throws<ObjectDisposedException>(() => cipher.Encrypt("hello"u8.ToArray(), new byte[33]));
    }
}
