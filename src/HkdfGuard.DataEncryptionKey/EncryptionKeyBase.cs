using HkdfGuard.Abstractions;
using HkdfGuard.Diagnostics;

namespace HkdfGuard.DataEncryptionKey;

public abstract class EncryptionKeyBase(ICryptoProvider provider) : IDataEncryptionKey
{
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
            var len = provider.GetEncryptedAllocationLength(plaintext.Length);
            Span<byte> buffer = new byte[len];
            var written = provider.Encrypt(plaintext, aad, buffer);
            return [.. buffer[..written]];
        }
        catch (Exception ex)
        {
            ComponentTelemetry.RecordException(activity, ex);
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
            return provider.Decrypt(ciphertext, aad, result);
        }
        catch (Exception ex)
        {
            ComponentTelemetry.RecordException(activity, ex);
            throw;
        }
    }
}