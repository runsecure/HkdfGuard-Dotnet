using System.Security.Cryptography;
using HkdfGuard.Abstractions;

namespace HkdfGuard.DataEncryptionKey;

public class PipelineKeyFactory
{
    private Lazy<IKeyWrapper> _lazyWrapper = new(() => new DummyKeyWrapper());
        
    public PipelineDataEncryptionKey Create(ICryptoProviderFactory factory, IFormatProvider formatProvider, int keyVersion = 0)
    {
        var bytes = new byte[32];
        RandomNumberGenerator.Fill(bytes);
        var provider = factory.CreateForPipeline(_lazyWrapper.Value, bytes);
        return new PipelineDataEncryptionKey(provider, bytes);
    }
}