namespace HkdfGuard.Abstractions;

public interface ICryptoProviderFactory
{
    public ICryptoProvider Create(IKeyWrapper wrapper, byte[] wrapped, int expirySeconds);

    public ICryptoProvider CreateEphemeral(IKeyWrapper wrapper, int expirySeconds);

    public ICryptoProvider CreateForPipeline(IKeyWrapper wrapper, byte[] notWrapped);
}