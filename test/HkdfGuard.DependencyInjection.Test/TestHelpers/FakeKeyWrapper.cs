using HkdfGuard.Abstractions;

namespace HkdfGuard.DependencyInjection.Test.TestHelpers;

/// <summary>
/// An IKeyWrapper that always reveals/generates the same fixed key - isolates AddKeyRing tests
/// from any real native KMS machinery.
/// </summary>
internal sealed class FakeKeyWrapper(byte[] key) : IKeyWrapper
{
    public int Encrypt(Span<byte> plaintext, Span<byte> result) => throw new NotSupportedException();
    public int Encrypt(Span<byte> plaintext, Span<byte> result, ReadOnlySpan<byte> aad) => throw new NotSupportedException();

    public int Decrypt(ReadOnlySpan<byte> wrapped, Span<byte> result)
    {
        key.CopyTo(result);
        return key.Length;
    }

    public int Decrypt(ReadOnlySpan<byte> wrapped, Span<byte> result, ReadOnlySpan<byte> aad) => Decrypt(wrapped, result);

    public int GenerateAndWrap(Span<byte> result)
    {
        key.CopyTo(result);
        return key.Length;
    }
}
