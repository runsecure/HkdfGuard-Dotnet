using HkdfGuard.Abstractions;

namespace HkdfGuard.DataEncryptionKey.Test.TestHelpers;

/// <summary>
/// An IKeyWrapper that always reveals/generates the same fixed key, tracking how many times
/// Decrypt/GenerateAndWrap were called - isolates
/// KeyWrappedDataEncryptionKey/EphemeralDataEncryptionKey/KeyRing tests from the real native KMS
/// machinery while still exercising real AES-GCM via a real ICryptoSession.
/// </summary>
internal sealed class FakeKeyWrapper(byte[] key) : IKeyWrapper
{
    public int DecryptCallCount { get; private set; }
    public int GenerateAndWrapCallCount { get; private set; }

    /// <summary>
    /// When set, Decrypt throws this instead of revealing the key - lets tests exercise a
    /// KeyWrappedDataEncryptionKey Encrypt/Decrypt catch block without depending on the real
    /// cipher failing.
    /// </summary>
    public Exception? ThrowOnDecrypt { get; set; }

    public int Encrypt(Span<byte> plaintext, Span<byte> result)
        => throw new NotSupportedException($"{nameof(FakeKeyWrapper)} only supports Decrypt.");

    public int Decrypt(ReadOnlySpan<byte> wrapped, Span<byte> result)
    {
        DecryptCallCount++;
        if (ThrowOnDecrypt is not null)
            throw ThrowOnDecrypt;

        key.CopyTo(result);
        return key.Length;
    }

    public int GenerateAndWrap(Span<byte> result)
    {
        GenerateAndWrapCallCount++;
        key.CopyTo(result);
        return key.Length;
    }
}
