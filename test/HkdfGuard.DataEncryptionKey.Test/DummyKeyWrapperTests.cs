namespace HkdfGuard.DataEncryptionKey.Test;

/// <summary>
/// DummyKeyWrapper stands in for the IKeyWrapper the pipeline flow's ICryptoProviderFactory.
/// CreateForPipeline requires but never actually calls (the DEK is used as-is, never wrapped) -
/// every member is an inert no-op.
/// </summary>
public class DummyKeyWrapperTests
{
    [Fact]
    public void Encrypt_ReturnsZero()
    {
        var wrapper = new DummyKeyWrapper();

        Assert.Equal(0, wrapper.Encrypt(new byte[32], new byte[64]));
    }

    [Fact]
    public void Decrypt_ReturnsZero()
    {
        var wrapper = new DummyKeyWrapper();

        Assert.Equal(0, wrapper.Decrypt(new byte[32], new byte[32]));
    }

    [Fact]
    public void GenerateAndWrap_ReturnsZero()
    {
        var wrapper = new DummyKeyWrapper();

        Assert.Equal(0, wrapper.GenerateAndWrap(new byte[32]));
    }
}
