using HkdfGuard.CryptoSession.AesGcm256.Test.TestHelpers;

namespace HkdfGuard.CryptoSession.AesGcm256.Test;

public class AesGcmCryptoProviderFactoryTests
{
    private static readonly AesGcmCryptoProviderFactory Factory = new();

    [Fact]
    public void Create_ProducesAWorkingProvider()
    {
        var wrapper = new FakeKeyWrapper();
        using var provider = Factory.Create(wrapper, "wrapped"u8.ToArray(), 60);

        var plaintext = "top secret"u8.ToArray();
        var encrypted = new byte[provider.GetEncryptedAllocationLength(plaintext.Length)];
        var written = provider.Encrypt(plaintext, encrypted);

        var decrypted = new byte[plaintext.Length];
        Assert.Equal(plaintext.Length, provider.Decrypt(encrypted.AsSpan(0, written), decrypted));
    }

    [Fact]
    public void CreateEphemeral_CallsGenerateAndWrapExactlyOnce()
    {
        var wrapper = new FakeKeyWrapper();

        using var provider = Factory.CreateEphemeral(wrapper, 60);

        Assert.Equal(1, wrapper.GenerateAndWrapCallCount);
    }

    [Fact]
    public void CreateEphemeral_ProducesAWorkingProvider()
    {
        var wrapper = new FakeKeyWrapper();
        using var provider = Factory.CreateEphemeral(wrapper, 60);

        var plaintext = "top secret"u8.ToArray();
        var expected = (byte[])plaintext.Clone();
        var encrypted = new byte[provider.GetEncryptedAllocationLength(plaintext.Length)];
        var written = provider.Encrypt(plaintext, encrypted);

        var decrypted = new byte[expected.Length];
        var decryptedLength = provider.Decrypt(encrypted.AsSpan(0, written), decrypted);

        Assert.Equal(expected.Length, decryptedLength);
        Assert.Equal(expected, decrypted);
    }

    [Fact]
    public void CreateForPipeline_NeverCallsTheKeyWrapper()
    {
        // CreateForPipeline uses the supplied bytes directly as the AES key - there is nothing to
        // wrap/unwrap, so the wrapper it's handed should never be invoked.
        var wrapper = new FakeKeyWrapper { ThrowOnDecrypt = new InvalidOperationException("should not be called") };
        var dek = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(dek);

        using var provider = Factory.CreateForPipeline(wrapper, dek);

        Assert.Equal(0, wrapper.DecryptCallCount);
        Assert.Equal(0, wrapper.GenerateAndWrapCallCount);
    }

    [Fact]
    public void CreateForPipeline_ProducesAWorkingProvider()
    {
        var wrapper = new FakeKeyWrapper();
        var dek = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(dek);
        using var provider = Factory.CreateForPipeline(wrapper, dek);

        var plaintext = "top secret"u8.ToArray();
        var expected = (byte[])plaintext.Clone();
        var encrypted = new byte[provider.GetEncryptedAllocationLength(plaintext.Length)];
        var written = provider.Encrypt(plaintext, encrypted);

        var decrypted = new byte[expected.Length];
        var decryptedLength = provider.Decrypt(encrypted.AsSpan(0, written), decrypted);

        Assert.Equal(expected.Length, decryptedLength);
        Assert.Equal(expected, decrypted);
    }

    [Fact]
    public void CreateForPipeline_ProviderDisposeDoesNotThrow()
    {
        // Regression test: the pipeline-only AesGcmCryptoProvider constructor used to leave its
        // background-refresh task field null, and Dispose unconditionally called
        // _refreshTask.Wait(), throwing a NullReferenceException.
        var wrapper = new FakeKeyWrapper();
        var dek = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(dek);
        var provider = Factory.CreateForPipeline(wrapper, dek);

        var ex = Record.Exception(provider.Dispose);

        Assert.Null(ex);
    }
}
