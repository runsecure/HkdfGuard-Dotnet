using HkdfGuard.Abstractions;
using HkdfGuard.CryptoSession.AesGcm256;

namespace HkdfGuard.DataEncryptionKey.Test.TestHelpers;

/// <summary>
/// An ICryptoProviderFactory that delegates to a real AesGcmCryptoProviderFactory (so callers get
/// a genuinely working ICryptoProvider back) while recording the arguments each method was
/// called with - lets KeyRingBuilder tests assert exactly what it passes through without
/// depending on AesGcmCryptoProvider exposing its own configuration for inspection.
/// </summary>
internal sealed class RecordingCryptoProviderFactory : ICryptoProviderFactory
{
    private readonly AesGcmCryptoProviderFactory _inner = new();

    public List<int> CreateExpirySecondsCalls { get; } = [];
    public List<int> CreateEphemeralExpirySecondsCalls { get; } = [];

    public ICryptoProvider Create(IKeyWrapper wrapper, byte[] wrapped, int expirySeconds)
    {
        CreateExpirySecondsCalls.Add(expirySeconds);
        return _inner.Create(wrapper, wrapped, expirySeconds);
    }

    public ICryptoProvider CreateEphemeral(IKeyWrapper wrapper, int expirySeconds)
    {
        CreateEphemeralExpirySecondsCalls.Add(expirySeconds);
        return _inner.CreateEphemeral(wrapper, expirySeconds);
    }

    public ICryptoProvider CreateForPipeline(IKeyWrapper wrapper, byte[] notWrapped)
        => _inner.CreateForPipeline(wrapper, notWrapped);
}
