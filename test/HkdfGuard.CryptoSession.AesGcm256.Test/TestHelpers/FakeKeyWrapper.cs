using HkdfGuard.Abstractions;

namespace HkdfGuard.CryptoSession.AesGcm256.Test.TestHelpers;

/// <summary>
/// An IKeyWrapper that always reveals a fresh random key, tracking how many times Decrypt was
/// called - isolates AesGcmCryptoSessionProvider tests from any real native KMS machinery.
/// </summary>
internal sealed class FakeKeyWrapper : IKeyWrapper
{
    public int DecryptCallCount { get; private set; }

    /// <summary>
    /// When set, Decrypt throws this instead of revealing a key.
    /// </summary>
    public Exception? ThrowOnDecrypt { get; set; }

    public int Encrypt(Span<byte> plaintext, Span<byte> result) => throw new NotSupportedException();
    public int Encrypt(Span<byte> plaintext, Span<byte> result, ReadOnlySpan<byte> aad) => throw new NotSupportedException();

    public int Decrypt(ReadOnlySpan<byte> wrapped, Span<byte> result)
    {
        DecryptCallCount++;
        if (ThrowOnDecrypt is not null)
            throw ThrowOnDecrypt;

        System.Security.Cryptography.RandomNumberGenerator.Fill(result);
        return result.Length;
    }

    public int Decrypt(ReadOnlySpan<byte> wrapped, Span<byte> result, ReadOnlySpan<byte> aad) => Decrypt(wrapped, result);
    public int GenerateAndWrap(Span<byte> result) => throw new NotSupportedException();
}
