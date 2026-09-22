using System.Runtime.InteropServices;

namespace HkdfGuard.KeyWrapping.V1.Interop;

/// <summary>
/// Binds HkdfGuard.Kms.MacOS.v1.dylib (see HkdfGuardKeyProtectionEnclave.h), which holds the
/// per-service KEK as a Secure Enclave key. Each distinct service string gets its own,
/// independent Secure Enclave key - wrapping under one service's identifier and unwrapping under
/// a different one fails by design (<see cref="ErrDecryptionFailed"/>).
/// </summary>
internal sealed partial class MacOsHkdfGuardKmsLibrary : AbstractHkdfGuardKmsLibrary
{
    private const string LibraryName = "HkdfGuard.Kms.MacOS.v1";

    public const int ErrInvalidInputLength = -1;
    public const int ErrOutputBufferTooSmall = -2;
    public const int ErrKeyUnavailable = -3;
    public const int ErrPublicKeyUnavailable = -4;
    public const int ErrEncryptionFailed = -5;
    public const int ErrDecryptionFailed = -6;
    public const int ErrUnexpectedOutputLength = -7;
    public const int ErrMissingServiceIdentifier = -8;

    public override int WrapDek(string service, ReadOnlySpan<byte> dek, Span<byte> destination, out int bytesWritten)
    {
        var outLen = destination.Length;
        var status = hkdfguard_wrap_dek(service, dek, dek.Length, destination, ref outLen);
        bytesWritten = outLen;
        return status;
    }

    public override int UnwrapDek(string service, ReadOnlySpan<byte> wrapped, Span<byte> destination, out int bytesWritten)
    {
        var outLen = destination.Length;
        var status = hkdfguard_unwrap_dek(service, wrapped, wrapped.Length, destination, ref outLen);
        bytesWritten = outLen;
        return status;
    }

    public override int GenerateAndWrapDek(string service, Span<byte> destination, out int bytesWritten)
    {
        var outLen = destination.Length;
        var status = hkdfguard_generate_and_wrap_dek(service, destination, ref outLen);
        bytesWritten = outLen;
        return status;
    }

    [LibraryImport(LibraryName, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int hkdfguard_wrap_dek(
        string service, ReadOnlySpan<byte> dek, int dekLen, Span<byte> output, ref int outLen);

    [LibraryImport(LibraryName, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int hkdfguard_unwrap_dek(
        string service, ReadOnlySpan<byte> wrapped, int wrappedLen, Span<byte> output, ref int outLen);

    [LibraryImport(LibraryName, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int hkdfguard_generate_and_wrap_dek(
        string service, Span<byte> output, ref int outLen);
}
