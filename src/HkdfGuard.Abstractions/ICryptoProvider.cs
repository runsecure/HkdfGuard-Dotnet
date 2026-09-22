namespace HkdfGuard.Abstractions;

/// <summary>
/// Tracks a single cached ICryptoSession, refreshing it (from a fresh key reveal/unwrap) once it
/// expires, and disposing the outgoing session as it does. Callers should call GetSession on
/// every operation rather than caching the returned ICryptoSession themselves, so they always see
/// a non-expired one.
/// </summary>
public interface ICryptoProvider : IDisposable
{
    /// <summary>
    /// Encrypt the data
    /// </summary>
    /// <param name="plaintext">Plain data to encrypt</param>
    /// <param name="result">The span to hold the encrypted data</param>
    /// <returns>Number of bytes written to the encrypted span</returns>
    public int Encrypt(Span<byte> plaintext, Span<byte> result);

    /// <summary>
    /// Encrypt the data
    /// </summary>
    /// <param name="plaintext">Plain data to encrypt</param>
    /// <param name="aad">The Additional Auth Data for the encrypt operation</param>
    /// <param name="result">The span to hold the encrypted data</param>
    /// <returns>Number of bytes written to the encrypted span</returns>
    public int Encrypt(Span<byte> plaintext, ReadOnlySpan<byte> aad, Span<byte> result);

    /// <summary>
    /// Decrypt the data
    /// </summary>
    /// <param name="ciphertext">The encrypted data to decrypt</param>
    /// <param name="result">The span to receive the decrypted data</param>
    /// <returns>The number of bytes written to the decrypted span</returns>
    public int Decrypt(ReadOnlySpan<byte> ciphertext, Span<byte> result);

    /// <summary>
    /// Decrypt the data
    /// </summary>
    /// <param name="ciphertext">The encrypted data to decrypt</param>
    /// <param name="aad">Additional Auth Data for the decrypt operation</param>
    /// <param name="result">The span to receive the decrypted data</param>
    /// <returns>The number of bytes written to the decrypted span</returns>
    public int Decrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> aad, Span<byte> result);
}
