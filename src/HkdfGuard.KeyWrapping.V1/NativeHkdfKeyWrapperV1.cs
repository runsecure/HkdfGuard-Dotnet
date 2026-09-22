using System.Security.Cryptography;
using HkdfGuard.Abstractions;
using HkdfGuard.KeyWrapping.V1.Interop;

namespace HkdfGuard.KeyWrapping.V1;

/// <summary>
/// Protects (Encrypt) a fresh DEK, or reveals (Decrypt) a previously-wrapped one, via the current
/// OS's native HkdfGuard KMS library (see NativeHost) - a TPM2, Secure Enclave, or Platform
/// Crypto Provider key held entirely outside this process, identified only by a service name. No
/// salt/blob machinery is involved: the native library owns the KEK, the wrapped payload's
/// format, and its own key derivation. Since Decrypt takes its wrapped payload as an explicit
/// argument rather than one bound at construction, a single instance freely handles both
/// directions, and any number of different wrapped payloads sharing the same service name. The
/// native ABI has no concept of AAD, so the 3-arg overloads accept only an empty aad; anything
/// else throws NotSupportedException.
/// </summary>
public class NativeHkdfKeyWrapperV1 : IKeyWrapper
{
    private readonly string _serviceName;
    private readonly AbstractHkdfGuardKmsLibrary _library;

    public NativeHkdfKeyWrapperV1(string serviceName)
        : this(serviceName, NativeHost.Library)
    {
    }

    internal NativeHkdfKeyWrapperV1(string serviceName, AbstractHkdfGuardKmsLibrary library)
    {
        _serviceName = serviceName;
        _library = library;
    }

    /// <inheritdoc/>
    public int Encrypt(Span<byte> plaintext, Span<byte> result)
    {
        var status = _library.WrapDek(_serviceName, plaintext, result, out var bytesWritten);
        return status == AbstractHkdfGuardKmsLibrary.Ok 
            ? bytesWritten 
            : throw new CryptographicException($"Native KMS wrap failed with status {status}.");
    }

    /// <inheritdoc/>
    public int Decrypt(ReadOnlySpan<byte> wrapped, Span<byte> result)
    {
        var status = _library.UnwrapDek(_serviceName, wrapped, result, out var bytesWritten);
        return status == AbstractHkdfGuardKmsLibrary.Ok 
            ? bytesWritten 
            : throw new CryptographicException($"Native KMS unwrap failed with status {status}.");
    }

    /// <inheritdoc/>
    public int GenerateAndWrap(Span<byte> result)
    {
        var status = _library.GenerateAndWrapDek(_serviceName, result, out var bytesWritten);
        return status == AbstractHkdfGuardKmsLibrary.Ok 
            ? bytesWritten 
            : throw new CryptographicException($"Native KMS generate-and-wrap failed with status {status}.");
    }
}
