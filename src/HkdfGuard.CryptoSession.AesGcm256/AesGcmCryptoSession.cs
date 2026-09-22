using System.Security.Cryptography;
using HkdfGuard.Abstractions;
using HkdfGuard.CryptoSession.AesGcm256.Diagnostics;

namespace HkdfGuard.CryptoSession.AesGcm256;

/// <summary>
/// An ICryptoSession backed by a single 32-byte AES-256 key, supplied once at construction. The
/// underlying AesGcm instance is built once here too (not per Encrypt/Decrypt call), so this
/// instance is meant to be held for a while - see ExpiresAt/ICryptoSessionProvider - and Disposed
/// (releasing the AesGcm instance and zeroing the key) once no longer needed rather than rebuilt
/// on every operation.
/// </summary>
internal class AesGcmCryptoSession : ICryptoSession
{
    private const int TagSize = 16;
    private const int NonceSize = 12;
    private const int KeyLength = 32;

    private readonly byte[] _key;
    private readonly AesGcm _aes;

    /// <inheritdoc/>
    public DateTimeOffset ExpiresAt { get; }

    /// <param name="key">The 32-byte AES-256 key this session encrypts/decrypts with - ownership
    /// transfers to this instance, which zeroes it on Dispose.</param>
    /// <param name="expirySeconds">How many seconds from now this session should be treated as
    /// valid for (see ExpiresAt) - not validated here, since this type is internal and its only
    /// caller (AesGcmCryptoSessionProvider) already validates it.</param>
    /// <exception cref="ArgumentException">key is empty/all-zero, or not exactly 32 bytes</exception>
    public AesGcmCryptoSession(byte[] key, int expirySeconds)
    {
        if (ArrayUtility.IsNullOrEmpty(key))
            throw new ArgumentException("AES key must not be empty or all zero.", nameof(key));

        if (key.Length != KeyLength)
            throw new ArgumentException($"AES key must be exactly {KeyLength} bytes.", nameof(key));

        _key = key;
        _aes = new AesGcm(key, TagSize);
        ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(expirySeconds);
    }

    /// <inheritdoc/>
    public int Encrypt(Span<byte> plaintext, Span<byte> result)
        => Encrypt(plaintext, ReadOnlySpan<byte>.Empty, result);

    /// <inheritdoc/>
    public int Encrypt(Span<byte> plaintext, ReadOnlySpan<byte> aad, Span<byte> result)
    {
        using var activity = AesGcm256Diagnostics.ActivitySource.StartActivity("AesGcmCryptoSession.Encrypt");
        if (AesGcm256Diagnostics.EnableSensitiveLogging)
            AesGcm256Diagnostics.LogSensitiveOperation(activity, "AesGcmCryptoSession.Encrypt",
                ("plaintextLength", plaintext.Length), ("aadLength", aad.Length));

        try
        {
            return CoreEncrypt(plaintext, aad, result);
        }
        catch (Exception ex)
        {
            AesGcm256Diagnostics.RecordException(activity, ex);
            throw;
        }
        finally
        {
            ArrayUtility.ZeroMemory(plaintext);
        }
    }

    private int CoreEncrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> aad, Span<byte> result)
    {
        if (ArrayUtility.IsNullOrEmpty(plaintext))
            throw new ArgumentException("Plaintext must not be empty or all zero.", nameof(plaintext));

        if (result.Length < NonceSize + plaintext.Length + TagSize)
            throw new ArgumentException("Result buffer too small.", nameof(result));

        // Layout: [nonce | ciphertext | tag]
        var nonce = result.Slice(0, NonceSize);
        var ciphertext = result.Slice(NonceSize, plaintext.Length);
        var tag = result.Slice(NonceSize + plaintext.Length, TagSize);

        RandomNumberGenerator.Fill(nonce);

        _aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);

        return NonceSize + plaintext.Length + TagSize;
    }

    /// <inheritdoc/>
    public int Decrypt(ReadOnlySpan<byte> ciphertext, Span<byte> result)
        => Decrypt(ciphertext, ReadOnlySpan<byte>.Empty, result);

    /// <inheritdoc/>
    public int Decrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> aad, Span<byte> result)
    {
        using var activity = AesGcm256Diagnostics.ActivitySource.StartActivity("AesGcmCryptoSession.Decrypt");
        if (AesGcm256Diagnostics.EnableSensitiveLogging)
            AesGcm256Diagnostics.LogSensitiveOperation(activity, "AesGcmCryptoSession.Decrypt",
                ("ciphertextLength", ciphertext.Length), ("aadLength", aad.Length));

        try
        {
            return CoreDecrypt(ciphertext, aad, result);
        }
        catch (Exception ex)
        {
            AesGcm256Diagnostics.RecordException(activity, ex);
            throw;
        }
    }

    private int CoreDecrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> aad, Span<byte> result)
    {
        if (ArrayUtility.IsNullOrEmpty(ciphertext))
            throw new ArgumentException("Ciphertext must not be empty or all zero.", nameof(ciphertext));

        if (ciphertext.Length < NonceSize + TagSize)
            throw new ArgumentException("Ciphertext too short.", nameof(ciphertext));

        var resultLength = ciphertext.Length - NonceSize - TagSize;

        if (result.Length < resultLength)
            throw new ArgumentException("Result buffer too small.", nameof(result));

        var nonce = ciphertext.Slice(0, NonceSize);
        var ct = ciphertext.Slice(NonceSize, resultLength);
        var tag = ciphertext.Slice(NonceSize + resultLength, TagSize);

        _aes.Decrypt(nonce, ct, tag, result.Slice(0, resultLength), aad);

        return resultLength;
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        _aes.Dispose();
        CryptographicOperations.ZeroMemory(_key);
    }
}
