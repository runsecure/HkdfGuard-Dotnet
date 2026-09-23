using HkdfGuard.Abstractions;

namespace HkdfGuard.DataEncryptionKey;

internal class DummyKeyWrapper : IKeyWrapper
{
    public int Encrypt(Span<byte> plaintext, Span<byte> result) => 0;

    public int Decrypt(ReadOnlySpan<byte> wrapped, Span<byte> result) => 0;

    public int GenerateAndWrap(Span<byte> result) => 0;
}