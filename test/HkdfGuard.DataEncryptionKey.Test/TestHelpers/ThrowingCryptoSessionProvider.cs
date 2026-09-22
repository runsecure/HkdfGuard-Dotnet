using HkdfGuard.Abstractions;

namespace HkdfGuard.DataEncryptionKey.Test.TestHelpers;

/// <summary>
/// An ICryptoSessionProvider whose GetSession always throws - isolates
/// KeyWrappedDataEncryptionKey's own catch/RecordException/rethrow behavior from any particular
/// ICryptoSessionProvider implementation's failure timing (e.g. AesGcmCryptoSessionProvider fails
/// at construction rather than at GetSession, since it builds its first session eagerly).
/// </summary>
internal sealed class ThrowingCryptoSessionProvider(Exception exception) : ICryptoSessionProvider
{
    public ICryptoSession GetSession() => throw exception;

    public void Dispose()
    {
    }
}
