using HkdfGuard.Abstractions;
using HkdfGuard.Diagnostics;

namespace HkdfGuard.DataEncryptionKey;

/// <summary>
/// An IDataProtectionKey backed by one wrapped DEK payload. sessionProvider owns revealing that
/// payload's key (from a fresh unwrap, once its cached ICryptoSession expires) and performing the
/// actual data encrypt/decrypt with it - see ICryptoSessionProvider. Every operation resolves
/// GetSession fresh rather than caching the session itself, so it always uses a non-expired one.
/// </summary>
public class KeyWrappedDataEncryptionKey(ICryptoSessionProvider sessionProvider) : IDataProtectionKey
{
    // ICryptoSession is cipher-agnostic, so its exact ciphertext overhead (nonce/tag for
    // AES-GCM, potentially something else for a swapped-in cipher) isn't known here - over-
    // allocate generously and trim to what it actually wrote.
    private const int MaxCipherOverhead = 64;

    /// <inheritdoc/>
    public byte[] Encrypt(Span<byte> plaintext)
        => Encrypt(plaintext, ReadOnlySpan<byte>.Empty);

    /// <inheritdoc/>
    public byte[] Encrypt(Span<byte> plaintext, ReadOnlySpan<byte> aad)
    {
        using var activity = HkdfGuardTelemetry.DataProtection.ActivitySource.StartActivity(ActivityNames.DataProtection.KeyWrappedKeyEncrypt);
        if (HkdfGuardTelemetry.DataProtection.EnableSensitiveLogging)
            HkdfGuardTelemetry.DataProtection.LogSensitiveOperation(activity, ActivityNames.DataProtection.KeyWrappedKeyEncrypt,
                (AttributeNames.PlaintextLength, plaintext.Length), (AttributeNames.AadLength, aad.Length));

        try
        {
            var session = sessionProvider.GetSession();
            var buffer = new byte[plaintext.Length + MaxCipherOverhead];
            var written = session.Encrypt(plaintext, aad, buffer);
            return buffer.AsSpan(0, written).ToArray();
        }
        catch (Exception ex)
        {
            HkdfGuardTelemetry.DataProtection.RecordException(activity, ex);
            throw;
        }
    }

    /// <inheritdoc/>
    public int Decrypt(ReadOnlySpan<byte> ciphertext, Span<byte> result)
        => Decrypt(ciphertext, ReadOnlySpan<byte>.Empty, result);

    /// <inheritdoc/>
    public int Decrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> aad, Span<byte> result)
    {
        using var activity = HkdfGuardTelemetry.DataProtection.ActivitySource.StartActivity(ActivityNames.DataProtection.KeyWrappedKeyDecrypt);
        if (HkdfGuardTelemetry.DataProtection.EnableSensitiveLogging)
            HkdfGuardTelemetry.DataProtection.LogSensitiveOperation(activity, ActivityNames.DataProtection.KeyWrappedKeyDecrypt,
                (AttributeNames.CiphertextLength, ciphertext.Length), (AttributeNames.AadLength, aad.Length));

        try
        {
            var session = sessionProvider.GetSession();
            return session.Decrypt(ciphertext, aad, result);
        }
        catch (Exception ex)
        {
            HkdfGuardTelemetry.DataProtection.RecordException(activity, ex);
            throw;
        }
    }
}
