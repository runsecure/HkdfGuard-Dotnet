using System.Runtime.InteropServices;
using HkdfGuard.KeyWrapping.V1.Interop;

namespace HkdfGuard.KeyWrapping.V1;

/// <summary>
/// Resolves the current OS's native HkdfGuard KMS library exactly once per process (binding the
/// wrong platform's library would fail on first native call anyway, so there's nothing to gain by
/// re-resolving per instance).
/// </summary>
internal static class NativeHost
{
    private static readonly Lazy<AbstractHkdfGuardKmsLibrary> LazyLibrary = new(Resolve);

    public static AbstractHkdfGuardKmsLibrary Library => LazyLibrary.Value;

    private static AbstractHkdfGuardKmsLibrary Resolve()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return new WindowsHkdfGuardKmsLibrary();

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            return new LinuxHkdfGuardKmsLibrary();

        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            return new MacOsHkdfGuardKmsLibrary();

        throw new PlatformNotSupportedException(
            $"HkdfGuard.KeyWrapping.V1 has no native KMS library for '{RuntimeInformation.OSDescription}'.");
    }
}
