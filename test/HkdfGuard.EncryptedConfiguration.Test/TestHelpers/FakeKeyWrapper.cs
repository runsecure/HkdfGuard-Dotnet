using HkdfGuard.Abstractions;

namespace HkdfGuard.EncryptedConfiguration.Test.TestHelpers;

/// <summary>
/// An IKeyWrapper that always reveals the same fixed key - isolates ProtectedConfigurationRoot
/// tests from the real blob/file/OS-storage machinery (already covered elsewhere) while still
/// exercising real AES-GCM via a real ICryptoSession.
/// </summary>
internal sealed class FakeKeyWrapper(byte[] key) : IKeyWrapper
{
    public int Encrypt(Span<byte> plaintext, Span<byte> result)
        => throw new NotSupportedException($"{nameof(FakeKeyWrapper)} only supports Decrypt.");

    public int Decrypt(ReadOnlySpan<byte> wrapped, Span<byte> result)
    {
        key.CopyTo(result);
        return key.Length;
    }

    public int GenerateAndWrap(Span<byte> result)
        => throw new NotSupportedException($"{nameof(FakeKeyWrapper)} only supports Decrypt.");
}
