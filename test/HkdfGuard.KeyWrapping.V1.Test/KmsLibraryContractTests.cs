using HkdfGuard.KeyWrapping.V1.Interop;

namespace HkdfGuard.KeyWrapping.V1.Test;

public class KmsLibraryContractTests
{
    [Fact]
    public void AbstractHkdfGuardKmsLibrary_Constants_MatchExpected()
    {
        Assert.Equal(32, AbstractHkdfGuardKmsLibrary.DekLength);
        Assert.Equal(0, AbstractHkdfGuardKmsLibrary.Ok);
    }

    [Fact]
    public void WindowsHkdfGuardKmsLibrary_ErrorConstants_MatchExpected()
    {
        Assert.Equal(-1, WindowsHkdfGuardKmsLibrary.ErrInvalidArg);
        Assert.Equal(-2, WindowsHkdfGuardKmsLibrary.ErrBufferTooSmall);
        Assert.Equal(-3, WindowsHkdfGuardKmsLibrary.ErrProvider);
        Assert.Equal(-4, WindowsHkdfGuardKmsLibrary.ErrCrypto);
        Assert.Equal(-5, WindowsHkdfGuardKmsLibrary.ErrAuthFailed);
        Assert.Equal(-6, WindowsHkdfGuardKmsLibrary.ErrMalformed);
        Assert.Equal(-7, WindowsHkdfGuardKmsLibrary.ErrInternal);
    }

    [Fact]
    public void LinuxHkdfGuardKmsLibrary_ErrorConstants_MatchExpected()
    {
        Assert.Equal(-1, LinuxHkdfGuardKmsLibrary.ErrInvalidArgument);
        Assert.Equal(-2, LinuxHkdfGuardKmsLibrary.ErrBufferTooSmall);
        Assert.Equal(-3, LinuxHkdfGuardKmsLibrary.ErrProviderUnavailable);
        Assert.Equal(-4, LinuxHkdfGuardKmsLibrary.ErrProviderError);
        Assert.Equal(-5, LinuxHkdfGuardKmsLibrary.ErrCryptoError);
        Assert.Equal(-6, LinuxHkdfGuardKmsLibrary.ErrInternalError);
        Assert.Equal(-7, LinuxHkdfGuardKmsLibrary.ErrInvalidUtf8);
        Assert.Equal(-8, LinuxHkdfGuardKmsLibrary.ErrMissingServiceName);
    }

    [Fact]
    public void MacOsHkdfGuardKmsLibrary_ErrorConstants_MatchExpected()
    {
        Assert.Equal(-1, MacOsHkdfGuardKmsLibrary.ErrInvalidInputLength);
        Assert.Equal(-2, MacOsHkdfGuardKmsLibrary.ErrOutputBufferTooSmall);
        Assert.Equal(-3, MacOsHkdfGuardKmsLibrary.ErrKeyUnavailable);
        Assert.Equal(-4, MacOsHkdfGuardKmsLibrary.ErrPublicKeyUnavailable);
        Assert.Equal(-5, MacOsHkdfGuardKmsLibrary.ErrEncryptionFailed);
        Assert.Equal(-6, MacOsHkdfGuardKmsLibrary.ErrDecryptionFailed);
        Assert.Equal(-7, MacOsHkdfGuardKmsLibrary.ErrUnexpectedOutputLength);
        Assert.Equal(-8, MacOsHkdfGuardKmsLibrary.ErrMissingServiceIdentifier);
    }
}
