using System.Security.Cryptography;
using HkdfGuard.Abstractions;
using HkdfGuard.Diagnostics;

namespace HkdfGuard.DataEncryptionKey;

/// <summary>
/// An IDataProtectionKey backed by a plain 32-byte DEK, used directly - never wrapped, never
/// unwrapped. Meant for a pipeline that needs to encrypt secrets in-flight before a durable KEK
/// exists yet: construct one (generating a fresh random DEK, or supplying an existing one),
/// encrypt whatever needs protecting during the pipeline, then read the same plaintext DEK back
/// via AsSpan at the end of the chain to hand off to the platform's native "initialize" CLI
/// utility, which independently wraps/registers it against a real KEK. Dispose zeroes the DEK.
/// </summary>
public sealed class PipelineDataEncryptionKey : IDataProtectionKey, IDisposable
{
    private const int DekLength = 32;

    private readonly byte[] _dek;
    private readonly ICryptoSessionProvider _sessionProvider;
    private readonly KeyWrappedDataEncryptionKey _inner;

    /// <summary>
    /// Generates a fresh, cryptographically random 32-byte DEK.
    /// </summary>
    /// <param name="sessionProviderFactory">See the other constructor overload.</param>
    public PipelineDataEncryptionKey(Func<IKeyWrapper, byte[], ICryptoSessionProvider> sessionProviderFactory)
        : this(RandomNumberGenerator.GetBytes(DekLength), sessionProviderFactory)
    {
    }

    /// <param name="dek">The plain 32-byte DEK to use as-is - ownership transfers to this
    /// instance, which zeroes it on Dispose.</param>
    /// <param name="sessionProviderFactory">
    /// Builds the ICryptoSessionProvider this instance encrypts/decrypts through (this class
    /// can't construct one directly - a concrete provider lives in whichever cipher package the
    /// caller chose, not here) - e.g.
    /// <c>(kw, wrapped) => new AesGcmCryptoSessionProvider(kw, wrapped, 60)</c>. Since dek needs
    /// no unwrapping, it's handed to that factory as both the key wrapper (an identity wrapper
    /// that reveals whatever "wrapped" bytes it's given, unchanged) and the wrapped payload
    /// itself.
    /// </param>
    /// <exception cref="ArgumentException">dek is empty/all-zero, or not exactly 32 bytes</exception>
    public PipelineDataEncryptionKey(byte[] dek, Func<IKeyWrapper, byte[], ICryptoSessionProvider> sessionProviderFactory)
    {
        if (ArrayUtility.IsNullOrEmpty(dek))
            throw new ArgumentException("DEK must not be empty or all zero.", nameof(dek));

        if (dek.Length != DekLength)
            throw new ArgumentException($"DEK must be exactly {DekLength} bytes.", nameof(dek));

        using var activity = HkdfGuardTelemetry.DataProtection.ActivitySource.StartActivity(ActivityNames.DataProtection.PipelineKeyInitialize);
        try
        {
            _dek = dek;
            _sessionProvider = sessionProviderFactory(new IdentityKeyWrapper(), dek);
            _inner = new KeyWrappedDataEncryptionKey(_sessionProvider);
        }
        catch (Exception ex)
        {
            HkdfGuardTelemetry.DataProtection.RecordException(activity, ex);
            throw;
        }
    }

    /// <summary>
    /// The plain, plaintext DEK this instance protects with - e.g. to hand off to the platform's
    /// native "initialize" CLI utility once the pipeline finishes.
    /// </summary>
    public Span<byte> AsSpan() => _dek;

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

    /// <summary>
    /// Disposes the underlying session provider/session, and zeroes the plaintext DEK.
    /// </summary>
    public void Dispose()
    {
        _sessionProvider.Dispose();
        CryptographicOperations.ZeroMemory(_dek);
    }

    // Treats the "wrapped" payload it's handed as already being the plaintext key - there is
    // nothing to unwrap, since this whole class's point is using a plain key as-is.
    private sealed class IdentityKeyWrapper : IKeyWrapper
    {
        public int Encrypt(Span<byte> plaintext, Span<byte> result)
            => throw new NotSupportedException($"{nameof(IdentityKeyWrapper)} only supports Decrypt.");

        public int Encrypt(Span<byte> plaintext, Span<byte> result, ReadOnlySpan<byte> aad)
            => throw new NotSupportedException($"{nameof(IdentityKeyWrapper)} only supports Decrypt.");

        public int Decrypt(ReadOnlySpan<byte> wrapped, Span<byte> result)
        {
            wrapped.CopyTo(result);
            return wrapped.Length;
        }

        public int Decrypt(ReadOnlySpan<byte> wrapped, Span<byte> result, ReadOnlySpan<byte> aad)
            => Decrypt(wrapped, result);

        public int GenerateAndWrap(Span<byte> result)
            => throw new NotSupportedException($"{nameof(IdentityKeyWrapper)} only supports Decrypt.");
    }
}
