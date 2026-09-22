namespace HkdfGuard.Abstractions;

/// <summary>
/// Protects (Encrypt) and reveals (Decrypt) an encryption key against a single, implicitly
/// identified KEK (e.g. a native KMS-backed key, identified by service name at construction).
/// Decrypt takes the wrapped payload as an explicit argument on every call, so one instance can
/// reveal any number of different wrapped keys sharing the same KEK - it holds no wrapped payload
/// of its own.
/// </summary>
public interface IKeyWrapper
{
    /// <summary>
    /// Protects an encryption key
    /// </summary>
    /// <param name="plaintext"></param>
    /// <param name="result">The encrypted key</param>
    /// <returns>Number of bytes written to the result</returns>
    public int Encrypt(Span<byte> plaintext, Span<byte> result);

    /// <summary>
    /// Reveals a previously-wrapped key
    /// </summary>
    /// <param name="wrapped">The wrapped key to reveal</param>
    /// <param name="result">The decrypted key span</param>
    /// <returns>Number of bytes written to the result</returns>
    public int Decrypt(ReadOnlySpan<byte> wrapped, Span<byte> result);

    /// <summary>
    /// Generates a fresh key and immediately protects it against the same KEK this instance
    /// wraps/reveals against - the plaintext key never crosses this call's return value.
    /// </summary>
    /// <param name="result">The wrapped key</param>
    /// <returns>Number of bytes written to the result</returns>
    public int GenerateAndWrap(Span<byte> result);
}
