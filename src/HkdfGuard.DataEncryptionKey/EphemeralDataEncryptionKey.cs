using HkdfGuard.Abstractions;
using HkdfGuard.Diagnostics;

namespace HkdfGuard.DataEncryptionKey;

/// <summary>
/// An IDataProtectionKey whose own DEK is never read from a file on disk - keyWrapper generates
/// and immediately wraps a fresh one in the constructor (see IKeyWrapper.GenerateAndWrap); the
/// plaintext DEK itself never crosses that call's return value. sessionProviderFactory then binds
/// an ICryptoSessionProvider to that wrapped payload (this class can't construct one directly - a
/// concrete provider lives in whichever cipher package the caller chose, not here). Every
/// Encrypt/Decrypt delegates to an inner KeyWrappedDataEncryptionKey built from that provider, the
/// same as a durable, file-backed key would use.
/// </summary>
public sealed class EphemeralDataEncryptionKey : IDataProtectionKey
{
    // IKeyWrapper.GenerateAndWrap is implementation-agnostic about its own wrapped-payload
    // format/size (a native KMS library's is a small fixed size, at most a few hundred bytes) -
    // over-allocate generously and trim to what it actually wrote, the same as
    // KeyWrappedDataEncryptionKey's MaxCipherOverhead does for cipher output.
    private const int MaxWrappedLength = 512;

    private readonly KeyWrappedDataEncryptionKey _inner;

    /// <param name="keyWrapper">Generates and wraps this instance's own fresh DEK.</param>
    /// <param name="sessionProviderFactory">
    /// Builds the ICryptoSessionProvider bound to keyWrapper and its freshly-generated wrapped
    /// payload - e.g. <c>(kw, wrapped) => new AesGcmCryptoSessionProvider(kw, wrapped, 60)</c>.
    /// </param>
    public EphemeralDataEncryptionKey(IKeyWrapper keyWrapper, Func<IKeyWrapper, byte[], ICryptoProvider> sessionProviderFactory)
    {
        using var activity = HkdfGuardTelemetry.DataProtection.ActivitySource.StartActivity(ActivityNames.DataProtection.EphemeralKeyInitialize);
        try
        {
            var buffer = new byte[MaxWrappedLength];
            var written = keyWrapper.GenerateAndWrap(buffer);
            var wrapped = buffer.AsSpan(0, written).ToArray();

            var sessionProvider = sessionProviderFactory(keyWrapper, wrapped);
            _inner = new KeyWrappedDataEncryptionKey(sessionProvider);
        }
        catch (Exception ex)
        {
            ComponentTelemetry.RecordException(activity, ex);
            throw;
        }
    }

    /// <inheritdoc/>
    public byte[] Encrypt(Span<byte> plaintext)
        => _inner.Encrypt(plaintext);

    /// <inheritdoc/>
    public byte[] Encrypt(Span<byte> plaintext, ReadOnlySpan<byte> aad)
        => _inner.Encrypt(plaintext, aad);

    /// <inheritdoc/>
    public int Decrypt(ReadOnlySpan<byte> ciphertext, Span<byte> result)
        => _inner.Decrypt(ciphertext, result);

    /// <inheritdoc/>
    public int Decrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> aad, Span<byte> result)
        => _inner.Decrypt(ciphertext, aad, result);
}
