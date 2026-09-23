using HkdfGuard.Abstractions;

namespace HkdfGuard.Cache.Test.TestHelpers;

/// <summary>
/// A minimal ProtectedCacheBase subclass whose TryPopulate is driven directly by the test - lets
/// tests exercise the base class's cache-miss-then-populate path without depending on any real
/// external source.
/// </summary>
internal sealed class PopulatingCache(IDataEncryptionKey dataEncryptionKey) : ProtectedCacheBase(dataEncryptionKey)
{
    public int TryPopulateCallCount { get; private set; }
    public Func<string, bool>? OnTryPopulate { get; set; }

    public void Seed(string name, Span<char> plaintext) => Data[name] = EncryptChars(plaintext);

    protected override bool TryPopulate(string name)
    {
        TryPopulateCallCount++;
        return OnTryPopulate?.Invoke(name) ?? false;
    }
}
