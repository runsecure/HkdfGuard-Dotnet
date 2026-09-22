using System.Runtime.InteropServices;

namespace HkdfGuard.KeyWrapping.V1.Interop;

/// <summary>
/// Binds HkdfGuard.Kms.Windows.v1.dll (see hkdfguard.h), which holds the per-service KEK as a
/// persistent, machine-wide-scoped, non-exportable P-256 key in the Microsoft Platform Crypto
/// Provider (TPM/vTPM) when available, or the Microsoft Software Key Storage Provider otherwise.
/// </summary>
internal sealed partial class WindowsHkdfGuardKmsLibrary : AbstractHkdfGuardKmsLibrary
{
    private const string LibraryName = "HkdfGuard.Kms.Windows.v1";

    public const int ErrInvalidArg = -1;
    public const int ErrBufferTooSmall = -2;
    public const int ErrProvider = -3;
    public const int ErrCrypto = -4;
    public const int ErrAuthFailed = -5;
    public const int ErrMalformed = -6;
    public const int ErrInternal = -7;

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
