using System.Security.Cryptography;
using HkdfGuard.KeyWrapping.V1.Interop;

namespace HkdfGuard.KeyWrapping.V1.Test;

/// <summary>
/// Integration tests verifying real key wrapping and unwrapping against the platform's native KMS
/// library (Windows Platform Crypto Provider / TPM, Linux TPM2/keyring/OpenSSL, macOS Secure Enclave).
/// When native shared libraries are not available on the execution host, these tests gracefully return
/// without failing unit test suites.
/// </summary>
public class NativeKeyWrappingIntegrationTests
{
    private static bool IsNativeLibraryAvailable()
    {
        try
        {
            var library = NativeHost.Library;
            Span<byte> testDest = stackalloc byte[512];
            // Probe invocation to check if the native binary is present and can be dynamically linked
            var status = library.WrapDek("hkdfguard-probe-service", new byte[32], testDest, out _);
            return true;
        }
        catch (DllNotFoundException)
        {
            return false;
        }
        catch (EntryPointNotFoundException)
        {
            return false;
        }
        catch (PlatformNotSupportedException)
        {
            return false;
        }
        catch
        {
            // Any other exception means the library binary loaded and executed
            return true;
        }
    }

    [Fact]
    public void NativeHkdfKeyWrapperV1_EncryptAndDecrypt_RoundTrips32ByteDek()
    {
        if (!IsNativeLibraryAvailable())
        {
            return;
        }

        var serviceName = $"hkdfguard-test-{Guid.NewGuid():N}";
        var wrapper = new NativeHkdfKeyWrapperV1(serviceName);

        var originalDek = RandomNumberGenerator.GetBytes(32);
        Span<byte> wrapped = stackalloc byte[512];
        var wrappedBytesWritten = wrapper.Encrypt(originalDek.AsSpan(), wrapped);

        Assert.True(wrappedBytesWritten > 0);
        Assert.False(wrapped[..wrappedBytesWritten].SequenceEqual(originalDek));

        Span<byte> unwrappedDek = stackalloc byte[32];
        var unwrappedBytesWritten = wrapper.Decrypt(wrapped[..wrappedBytesWritten], unwrappedDek);

        Assert.Equal(32, unwrappedBytesWritten);
        Assert.Equal(originalDek, unwrappedDek.ToArray());
    }

    [Fact]
    public void NativeHkdfKeyWrapperV1_GenerateAndWrapAndDecrypt_ProducesValid32ByteDek()
    {
        if (!IsNativeLibraryAvailable())
        {
            return;
        }

        var serviceName = $"hkdfguard-test-{Guid.NewGuid():N}";
        var wrapper = new NativeHkdfKeyWrapperV1(serviceName);

        Span<byte> wrapped = stackalloc byte[512];
        var wrappedBytesWritten = wrapper.GenerateAndWrap(wrapped);

        Assert.True(wrappedBytesWritten > 0);

        Span<byte> recoveredDek1 = stackalloc byte[32];
        var unwrappedBytes1 = wrapper.Decrypt(wrapped[..wrappedBytesWritten], recoveredDek1);

        Assert.Equal(32, unwrappedBytes1);
        Assert.False(recoveredDek1.ToArray().All(b => b == 0));

        Span<byte> recoveredDek2 = stackalloc byte[32];
        var unwrappedBytes2 = wrapper.Decrypt(wrapped[..wrappedBytesWritten], recoveredDek2);

        Assert.Equal(32, unwrappedBytes2);
        Assert.Equal(recoveredDek1.ToArray(), recoveredDek2.ToArray());
    }

    [Fact]
    public void NativeHkdfKeyWrapperV1_ServiceIsolation_CannotDecryptPayloadFromDifferentService()
    {
        if (!IsNativeLibraryAvailable())
        {
            return;
        }

        var serviceA = $"hkdfguard-service-a-{Guid.NewGuid():N}";
        var serviceB = $"hkdfguard-service-b-{Guid.NewGuid():N}";

        var wrapperA = new NativeHkdfKeyWrapperV1(serviceA);
        var wrapperB = new NativeHkdfKeyWrapperV1(serviceB);

        var originalDek = RandomNumberGenerator.GetBytes(32);
        var wrapped = new byte[512];
        var wrappedLen = wrapperA.Encrypt(originalDek.AsSpan(), wrapped.AsSpan());

        var destination = new byte[32];
        Assert.Throws<CryptographicException>(() =>
            wrapperB.Decrypt(wrapped.AsSpan(0, wrappedLen), destination.AsSpan()));
    }

    [Fact]
    public void NativeHkdfKeyWrapperV1_MultipleKeysUnderSameService_WrapAndUnwrapIndependently()
    {
        if (!IsNativeLibraryAvailable())
        {
            return;
        }

        var serviceName = $"hkdfguard-multi-{Guid.NewGuid():N}";
        var wrapper = new NativeHkdfKeyWrapperV1(serviceName);

        var dek1 = RandomNumberGenerator.GetBytes(32);
        var dek2 = RandomNumberGenerator.GetBytes(32);

        Span<byte> wrapped1 = stackalloc byte[512];
        Span<byte> wrapped2 = stackalloc byte[512];

        var len1 = wrapper.Encrypt(dek1.AsSpan(), wrapped1);
        var len2 = wrapper.Encrypt(dek2.AsSpan(), wrapped2);

        Span<byte> recovered1 = stackalloc byte[32];
        Span<byte> recovered2 = stackalloc byte[32];

        var recoveredLen1 = wrapper.Decrypt(wrapped1[..len1], recovered1);
        var recoveredLen2 = wrapper.Decrypt(wrapped2[..len2], recovered2);

        Assert.Equal(32, recoveredLen1);
        Assert.Equal(32, recoveredLen2);
        Assert.Equal(dek1, recovered1.ToArray());
        Assert.Equal(dek2, recovered2.ToArray());
    }

    [Fact]
    public void NativeHostLibrary_DirectWrapAndUnwrap_ReturnsOkStatusAndRecoversDek()
    {
        if (!IsNativeLibraryAvailable())
        {
            return;
        }

        var library = NativeHost.Library;
        var serviceName = $"hkdfguard-direct-{Guid.NewGuid():N}";
        var dek = RandomNumberGenerator.GetBytes(32);

        Span<byte> wrapped = stackalloc byte[512];
        var wrapStatus = library.WrapDek(serviceName, dek.AsSpan(), wrapped, out var bytesWritten);

        Assert.Equal(AbstractHkdfGuardKmsLibrary.Ok, wrapStatus);
        Assert.True(bytesWritten > 0);

        Span<byte> recovered = stackalloc byte[32];
        var unwrapStatus = library.UnwrapDek(serviceName, wrapped[..bytesWritten], recovered, out var unwrapBytes);

        Assert.Equal(AbstractHkdfGuardKmsLibrary.Ok, unwrapStatus);
        Assert.Equal(32, unwrapBytes);
        Assert.Equal(dek, recovered.ToArray());
    }

    [Fact]
    public void NativeHostLibrary_DirectGenerateAndWrapDek_ReturnsOkStatusAndProducesValidPayload()
    {
        if (!IsNativeLibraryAvailable())
        {
            return;
        }

        var library = NativeHost.Library;
        var serviceName = $"hkdfguard-direct-gen-{Guid.NewGuid():N}";

        Span<byte> wrapped = stackalloc byte[512];
        var genStatus = library.GenerateAndWrapDek(serviceName, wrapped, out var bytesWritten);

        Assert.Equal(AbstractHkdfGuardKmsLibrary.Ok, genStatus);
        Assert.True(bytesWritten > 0);

        Span<byte> recovered = stackalloc byte[32];
        var unwrapStatus = library.UnwrapDek(serviceName, wrapped[..bytesWritten], recovered, out var unwrapBytes);

        Assert.Equal(AbstractHkdfGuardKmsLibrary.Ok, unwrapStatus);
        Assert.Equal(32, unwrapBytes);
        Assert.False(recovered.ToArray().All(b => b == 0));
    }

    [Fact]
    public void NativeHostLibrary_WrapDek_WithInsufficientBuffer_ReturnsError()
    {
        if (!IsNativeLibraryAvailable())
        {
            return;
        }

        var library = NativeHost.Library;
        var serviceName = $"hkdfguard-short-buf-{Guid.NewGuid():N}";
        var dek = RandomNumberGenerator.GetBytes(32);

        Span<byte> tinyBuffer = stackalloc byte[1];
        var status = library.WrapDek(serviceName, dek.AsSpan(), tinyBuffer, out var requiredBytes);

        Assert.True(status < 0);
        Assert.True(requiredBytes > 1);
    }

    [Fact]
    public void NativeHostLibrary_UnwrapDek_WithInsufficientBuffer_ReturnsError()
    {
        if (!IsNativeLibraryAvailable())
        {
            return;
        }

        var library = NativeHost.Library;
        var serviceName = $"hkdfguard-unwrap-short-buf-{Guid.NewGuid():N}";
        var dek = RandomNumberGenerator.GetBytes(32);

        Span<byte> wrapped = stackalloc byte[512];
        var wrapStatus = library.WrapDek(serviceName, dek.AsSpan(), wrapped, out var bytesWritten);
        Assert.Equal(AbstractHkdfGuardKmsLibrary.Ok, wrapStatus);

        Span<byte> tinyDestination = stackalloc byte[1];
        var status = library.UnwrapDek(serviceName, wrapped[..bytesWritten], tinyDestination, out _);

        Assert.True(status < 0);
    }

    [Fact]
    public void NativeHostLibrary_GenerateAndWrapDek_WithInsufficientBuffer_ReturnsError()
    {
        if (!IsNativeLibraryAvailable())
        {
            return;
        }

        var library = NativeHost.Library;
        var serviceName = $"hkdfguard-gen-short-buf-{Guid.NewGuid():N}";

        Span<byte> tinyBuffer = stackalloc byte[1];
        var status = library.GenerateAndWrapDek(serviceName, tinyBuffer, out _);

        Assert.True(status < 0);
    }

    [Fact]
    public void NativeHostLibrary_UnwrapDek_WithCorruptedPayload_ReturnsError()
    {
        if (!IsNativeLibraryAvailable())
        {
            return;
        }

        var library = NativeHost.Library;
        var serviceName = $"hkdfguard-corrupt-{Guid.NewGuid():N}";
        var dek = RandomNumberGenerator.GetBytes(32);

        Span<byte> wrapped = stackalloc byte[512];
        var wrapStatus = library.WrapDek(serviceName, dek.AsSpan(), wrapped, out var bytesWritten);
        Assert.Equal(AbstractHkdfGuardKmsLibrary.Ok, wrapStatus);

        // Corrupt the wrapped payload bytes
        wrapped[0] ^= 0xFF;
        wrapped[bytesWritten / 2] ^= 0xFF;

        Span<byte> recovered = stackalloc byte[32];
        var unwrapStatus = library.UnwrapDek(serviceName, wrapped[..bytesWritten], recovered, out _);

        Assert.True(unwrapStatus < 0);
    }
}
