using System.Security.Cryptography;
using HkdfGuard.Abstractions;
using HkdfGuard.Diagnostics;

namespace HkdfGuard.DataEncryptionKey;

/// <summary>
/// An IDataEncryptionKey backed by a plain 32-byte DEK, used directly - never wrapped, never
/// unwrapped. Meant for a pipeline that needs to encrypt secrets in-flight before a durable KEK
/// exists yet: construct one (generating a fresh random DEK, or supplying an existing one),
/// encrypt whatever needs protecting during the pipeline, then read the same plaintext DEK back
/// via AsSpan at the end of the chain to hand off to the platform's native "initialize" CLI
/// utility, which independently wraps/registers it against a real KEK. Dispose zeroes the DEK.
/// </summary>
public sealed class PipelineDataEncryptionKey(ICryptoProvider provider, byte[] dek) : EncryptionKeyBase(provider), IDisposable
{
    private readonly byte[] _dek = dek;

    /// <summary>
    /// The plain, plaintext DEK this instance protects with - e.g. to hand off to the platform's
    /// native "initialize" CLI utility once the pipeline finishes.
    /// </summary>
    public Span<byte> AsSpan() => _dek;

    /// <summary>
    /// Disposes the underlying session provider/session, and zeroes the plaintext DEK.
    /// </summary>
    public void Dispose()
    {
        provider.Dispose();
        ArrayUtility.ZeroMemory(_dek);
    }
}
