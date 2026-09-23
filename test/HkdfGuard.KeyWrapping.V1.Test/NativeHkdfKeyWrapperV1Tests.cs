using System.Security.Cryptography;
using HkdfGuard.KeyWrapping.V1.Interop;
using HkdfGuard.KeyWrapping.V1.Test.TestHelpers;

namespace HkdfGuard.KeyWrapping.V1.Test;

public class NativeHkdfKeyWrapperV1Tests
{
    [Fact]
    public void Constructor_WithServiceName_InstantiatesSuccessfully()
    {
        var wrapper = new NativeHkdfKeyWrapperV1("test-service");

        Assert.NotNull(wrapper);
    }

    [Fact]
    public void Encrypt_DelegatesToLibrary()
    {
        var fakeLibrary = new FakeHkdfGuardKmsLibrary
        {
            WrapPayloadToEmit = new byte[] { 10, 20, 30, 40 }
        };
        var wrapper = new NativeHkdfKeyWrapperV1("service-a", fakeLibrary);

        var plaintext = new byte[] { 1, 2, 3, 4, 5 };
        var resultBuffer = new byte[16];

        var bytesWritten = wrapper.Encrypt(plaintext.AsSpan(), resultBuffer.AsSpan());

        Assert.Equal(4, bytesWritten);
        Assert.Equal(1, fakeLibrary.WrapCallCount);
        Assert.Equal("service-a", fakeLibrary.LastService);
        Assert.Equal(plaintext, fakeLibrary.LastWrapPlaintext);
        Assert.Equal(new byte[] { 10, 20, 30, 40 }, resultBuffer[..4]);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(-2)]
    [InlineData(-7)]
    public void Encrypt_WhenLibraryFails_ThrowsCryptographicException(int errorCode)
    {
        var fakeLibrary = new FakeHkdfGuardKmsLibrary
        {
            WrapDekStatus = errorCode
        };
        var wrapper = new NativeHkdfKeyWrapperV1("service-d", fakeLibrary);

        var plaintext = new byte[] { 1, 2, 3 };
        var resultBuffer = new byte[8];

        var exception = Assert.Throws<CryptographicException>(() =>
            wrapper.Encrypt(plaintext.AsSpan(), resultBuffer.AsSpan()));

        Assert.Equal($"Native KMS wrap failed with status {errorCode}.", exception.Message);
        Assert.Equal(1, fakeLibrary.WrapCallCount);
    }

    [Fact]
    public void Decrypt_DelegatesToLibrary()
    {
        var fakeLibrary = new FakeHkdfGuardKmsLibrary
        {
            UnwrapPayloadToEmit = new byte[] { 1, 2, 3, 4, 5 }
        };
        var wrapper = new NativeHkdfKeyWrapperV1("service-a", fakeLibrary);

        var wrapped = new byte[] { 10, 20, 30, 40 };
        var resultBuffer = new byte[16];

        var bytesWritten = wrapper.Decrypt(wrapped.AsSpan(), resultBuffer.AsSpan());

        Assert.Equal(5, bytesWritten);
        Assert.Equal(1, fakeLibrary.UnwrapCallCount);
        Assert.Equal("service-a", fakeLibrary.LastService);
        Assert.Equal(wrapped, fakeLibrary.LastUnwrapWrapped);
        Assert.Equal(new byte[] { 1, 2, 3, 4, 5 }, resultBuffer[..5]);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(-2)]
    [InlineData(-6)]
    public void Decrypt_WhenLibraryFails_ThrowsCryptographicException(int errorCode)
    {
        var fakeLibrary = new FakeHkdfGuardKmsLibrary
        {
            UnwrapDekStatus = errorCode
        };
        var wrapper = new NativeHkdfKeyWrapperV1("service-d", fakeLibrary);

        var wrapped = new byte[] { 10, 20, 30 };
        var resultBuffer = new byte[8];

        var exception = Assert.Throws<CryptographicException>(() =>
            wrapper.Decrypt(wrapped.AsSpan(), resultBuffer.AsSpan()));

        Assert.Equal($"Native KMS unwrap failed with status {errorCode}.", exception.Message);
        Assert.Equal(1, fakeLibrary.UnwrapCallCount);
    }

    [Fact]
    public void GenerateAndWrap_DelegatesToLibrary()
    {
        var fakeLibrary = new FakeHkdfGuardKmsLibrary
        {
            GenerateAndWrapPayloadToEmit = new byte[] { 11, 22, 33, 44, 55 }
        };
        var wrapper = new NativeHkdfKeyWrapperV1("service-e", fakeLibrary);

        var resultBuffer = new byte[16];

        var bytesWritten = wrapper.GenerateAndWrap(resultBuffer.AsSpan());

        Assert.Equal(5, bytesWritten);
        Assert.Equal(1, fakeLibrary.GenerateAndWrapCallCount);
        Assert.Equal("service-e", fakeLibrary.LastService);
        Assert.Equal(new byte[] { 11, 22, 33, 44, 55 }, resultBuffer[..5]);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(-3)]
    [InlineData(-7)]
    public void GenerateAndWrap_WhenLibraryFails_ThrowsCryptographicException(int errorCode)
    {
        var fakeLibrary = new FakeHkdfGuardKmsLibrary
        {
            GenerateAndWrapDekStatus = errorCode
        };
        var wrapper = new NativeHkdfKeyWrapperV1("service-f", fakeLibrary);

        var resultBuffer = new byte[16];

        var exception = Assert.Throws<CryptographicException>(() =>
            wrapper.GenerateAndWrap(resultBuffer.AsSpan()));

        Assert.Equal($"Native KMS generate-and-wrap failed with status {errorCode}.", exception.Message);
        Assert.Equal(1, fakeLibrary.GenerateAndWrapCallCount);
    }
}
