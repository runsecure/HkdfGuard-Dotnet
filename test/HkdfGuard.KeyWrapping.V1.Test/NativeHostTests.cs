using System.Runtime.InteropServices;
using HkdfGuard.KeyWrapping.V1.Interop;

namespace HkdfGuard.KeyWrapping.V1.Test;

public class NativeHostTests
{
    [Fact]
    public void Library_ReturnsNonNullInstance()
    {
        var library = NativeHost.Library;

        Assert.NotNull(library);
    }

    [Fact]
    public void Library_ReturnsSameInstanceAcrossCalls()
    {
        var first = NativeHost.Library;
        var second = NativeHost.Library;

        Assert.Same(first, second);
    }

    [Fact]
    public void Library_ReturnsMatchingPlatformImplementation()
    {
        var library = NativeHost.Library;

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            Assert.IsType<WindowsHkdfGuardKmsLibrary>(library);
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            Assert.IsType<LinuxHkdfGuardKmsLibrary>(library);
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            Assert.IsType<MacOsHkdfGuardKmsLibrary>(library);
        }
        else
        {
            Assert.IsAssignableFrom<AbstractHkdfGuardKmsLibrary>(library);
        }
    }
}
