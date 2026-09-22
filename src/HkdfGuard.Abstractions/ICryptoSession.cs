namespace HkdfGuard.Abstractions;

/// <summary>
/// A live, key-bound symmetric-cipher session: the key is supplied once, at construction (not
/// per-call), and this instance holds it - and whatever native resources the cipher needs - until
/// Disposed. ExpiresAt marks when a caller (see ICryptoSessionProvider) should treat this session
/// as stale and refresh it, rather than reuse it indefinitely.
/// </summary>
public interface ICryptoSession : IDisposable
{
    /// <summary>
    /// The instant after which this session should no longer be reused.
    /// </summary>
    public DateTimeOffset ExpiresAt { get; }

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
