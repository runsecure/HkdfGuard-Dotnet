using System.Security.Cryptography;
using HkdfGuard.Abstractions;
using HkdfGuard.DataEncryptionKey;
using HkdfGuard.DataEncryptionKey.Test.TestHelpers;
using HkdfGuard.CryptoSession.AesGcm256;

namespace HkdfGuard.DataEncryptionKey.Test;

public class EphemeralDataEncryptionKeyTests
{
    private static readonly Func<IKeyWrapper, byte[], ICryptoProvider> SessionProviderFactory =
        (keyWrapper, wrapped) => new AesGcmCryptoProvider(keyWrapper, wrapped, 60);

    [Fact]
    public void Constructor_GeneratesWrappedDekExactlyOnce()
    {
        var wrapper = new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32));

        _ = new EphemeralDataEncryptionKey(wrapper, SessionProviderFactory);

        Assert.Equal(1, wrapper.GenerateAndWrapCallCount);
    }

    [Fact]
    public void EncryptDecrypt_RoundTrips()
    {
        var wrapper = new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32));
        var key = new EphemeralDataEncryptionKey(wrapper, SessionProviderFactory);
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
        var wrapper = new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32));
        var key = new EphemeralDataEncryptionKey(wrapper, SessionProviderFactory);
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
        var wrapper = new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32));
        var key = new EphemeralDataEncryptionKey(wrapper, SessionProviderFactory);
        var encrypted = key.Encrypt("top secret"u8.ToArray(), "context-a"u8.ToArray());

        Assert.Throws<AuthenticationTagMismatchException>(() =>
            key.Decrypt(encrypted, "context-b"u8.ToArray(), new byte[16]));
    }

    [Fact]
    public void EncryptAndDecrypt_ReuseTheSameGeneratedKeyAcrossCalls()
    {
        var wrapper = new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32));
        var key = new EphemeralDataEncryptionKey(wrapper, SessionProviderFactory);

        var encrypted1 = key.Encrypt("first"u8.ToArray());
        var encrypted2 = key.Encrypt("second"u8.ToArray());

        var result1 = new byte[5];
        var result2 = new byte[6];
        key.Decrypt(encrypted1, result1);
        key.Decrypt(encrypted2, result2);

        Assert.Equal("first", System.Text.Encoding.UTF8.GetString(result1));
        Assert.Equal("second", System.Text.Encoding.UTF8.GetString(result2));
        Assert.Equal(1, wrapper.GenerateAndWrapCallCount);
    }

    [Fact]
    public void EncryptAndDecrypt_ReuseTheCachedSessionAcrossCalls()
    {
        // AesGcmCryptoSessionProvider only calls back into the key wrapper when it has no cached
        // session yet or the cached one has expired - not on every operation - so the wrapper's
        // key is revealed once here, then reused for every subsequent Encrypt/Decrypt.
        var wrapper = new FakeKeyWrapper(RandomNumberGenerator.GetBytes(32));
        var key = new EphemeralDataEncryptionKey(wrapper, SessionProviderFactory);
        var encrypted = key.Encrypt("value"u8.ToArray());

        key.Decrypt(encrypted, new byte[5]);
        key.Decrypt(encrypted, new byte[5]);

        Assert.Equal(1, wrapper.DecryptCallCount);
    }
}
