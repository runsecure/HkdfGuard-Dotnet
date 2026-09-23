using HkdfGuard.Abstractions;

namespace HkdfGuard.CryptoSession.AesGcm256;

public class AesGcmCryptoProviderFactory : ICryptoProviderFactory
{
    public ICryptoProvider Create(IKeyWrapper wrapper, byte[] wrapped, int expirySeconds)
        => new AesGcmCryptoProvider(wrapper, wrapped, expirySeconds);

    public ICryptoProvider CreateEphemeral(IKeyWrapper wrapper, int expirySeconds)
    {
        Span<byte> wrapped = new byte[512];
        var len = wrapper.GenerateAndWrap(wrapped);
        var wrappedBytes = wrapped[..len].ToArray();
        return new AesGcmCryptoProvider(wrapper, wrappedBytes, expirySeconds);
    }

    public ICryptoProvider CreateForPipeline(IKeyWrapper wrapper, byte[] notWrapped)
        => new AesGcmCryptoProvider(wrapper, notWrapped);
}