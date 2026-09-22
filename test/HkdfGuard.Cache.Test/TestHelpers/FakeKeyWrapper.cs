using HkdfGuard.Abstractions;

namespace HkdfGuard.Cache.Test.TestHelpers;

/// <summary>
/// An IKeyWrapper that always reveals the same fixed key - isolates ProtectedCache tests from the
/// real blob/file/OS-storage machinery (already covered elsewhere) while still exercising real
/// AES-GCM via a real ICryptoSession.
/// </summary>
internal sealed class FakeKeyWrapper(byte[] key) : IKeyWrapper
{
    public int Encrypt(Span<byte> plaintext, Span<byte> result)
        => throw new NotSupportedException($"{nameof(FakeKeyWrapper)} only supports Decrypt.");

    public int Encrypt(Span<byte> plaintext, Span<byte> result, ReadOnlySpan<byte> aad)
        => throw new NotSupportedException($"{nameof(FakeKeyWrapper)} only supports Decrypt.");

    public int Decrypt(ReadOnlySpan<byte> wrapped, Span<byte> result)
    {
        key.CopyTo(result);
        return key.Length;
    }

    public int Decrypt(ReadOnlySpan<byte> wrapped, Span<byte> result, ReadOnlySpan<byte> aad)
        => Decrypt(wrapped, result);

    public int GenerateAndWrap(Span<byte> result)
        => throw new NotSupportedException($"{nameof(FakeKeyWrapper)} only supports Decrypt.");
}
