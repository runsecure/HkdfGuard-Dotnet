using HkdfGuard.Abstractions;

namespace HkdfGuard.Options.Test.TestHelpers;

/// <summary>
/// An IKeyWrapper that always reveals/generates the same fixed key - isolates ApplyTo/Build
/// integration tests from the real native KMS machinery while still exercising a real
/// KeyRingBuilder.Build.
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
    {
        key.CopyTo(result);
        return key.Length;
    }
}
