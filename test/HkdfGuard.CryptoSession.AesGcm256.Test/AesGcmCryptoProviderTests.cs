using HkdfGuard.CryptoSession.AesGcm256.Test.TestHelpers;

namespace HkdfGuard.CryptoSession.AesGcm256.Test;

public class AesGcmCryptoProviderTests
{
    [Fact]
    public void Constructor_BuildsInitialSessionEagerly()
    {
        var wrapper = new FakeKeyWrapper();

        using var provider = new AesGcmCryptoProvider(wrapper, "wrapped"u8.ToArray(), 60);

        Assert.Equal(1, wrapper.DecryptCallCount);
    }

    [Fact]
    public void Constructor_WhenKeyWrapperFails_Throws()
    {
        var wrapper = new FakeKeyWrapper { ThrowOnDecrypt = new InvalidOperationException("reveal failed") };

        Assert.Throws<InvalidOperationException>(() => new AesGcmCryptoProvider(wrapper, "wrapped"u8.ToArray(), 60));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(301)]
    public void Constructor_WithExpirySecondsOutOfRange_ThrowsArgumentOutOfRangeException(int expirySeconds)
    {
        var wrapper = new FakeKeyWrapper();

        Assert.Throws<ArgumentOutOfRangeException>(() => new AesGcmCryptoProvider(wrapper, "wrapped"u8.ToArray(), expirySeconds));
    }

    [Fact]
    public void BackgroundTimer_ProactivelyRefreshesTheSessionWithoutAnyGetSessionCall()
    {
        var wrapper = new FakeKeyWrapper();
        using var provider = new AesGcmCryptoProvider(wrapper, "wrapped"u8.ToArray(), 1);

        // No GetSession call at all - only the constructor's eager build (DecryptCallCount == 1)
        // and the background timer, ticking every expirySeconds, should have run by now.
        Thread.Sleep(TimeSpan.FromSeconds(1.5));

        Assert.Equal(2, wrapper.DecryptCallCount);
    }

    [Fact]
    public void Dispose_DisposesTheCurrentSessionAndStopsTheBackgroundTimer()
    {
        var wrapper = new FakeKeyWrapper();
        var provider = new AesGcmCryptoProvider(wrapper, "wrapped"u8.ToArray(), 1);

        provider.Dispose();
        Thread.Sleep(TimeSpan.FromSeconds(1.5));

        // Only the constructor's eager build - the timer must not have fired after Dispose.
        Assert.Equal(1, wrapper.DecryptCallCount);
    }

    [Fact]
    public void GetEncryptedAllocationLength_AddsNonceAndTagOverhead()
    {
        var wrapper = new FakeKeyWrapper();
        using var provider = new AesGcmCryptoProvider(wrapper, "wrapped"u8.ToArray(), 60);

        Assert.Equal(10 + 12 + 16, provider.GetEncryptedAllocationLength(10));
    }

    [Fact]
    public void GetDecryptedAllocationLength_RemovesNonceAndTagOverhead()
    {
        var wrapper = new FakeKeyWrapper();
        using var provider = new AesGcmCryptoProvider(wrapper, "wrapped"u8.ToArray(), 60);

        Assert.Equal(10, provider.GetDecryptedAllocationLength(10 + 12 + 16));
    }
}
