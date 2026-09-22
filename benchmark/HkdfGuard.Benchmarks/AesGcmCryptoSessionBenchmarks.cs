using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using HkdfGuard.Abstractions;
using HkdfGuard.CryptoSession.AesGcm256;

namespace HkdfGuard.Benchmarks;

/// <summary>
/// Benchmarks AesGcmCryptoSession.Encrypt/Decrypt (via AesGcmCryptoSessionProvider, since the
/// session type itself is internal to HkdfGuard.CryptoSession.AesGcm256) - the raw
/// symmetric-cipher cost underlying every higher-level operation in this library, isolated from
/// key derivation and storage. The key is bound once at construction, so unlike Encrypt's
/// plaintext argument (zeroed as a side effect once it's done with it, refreshed from a pristine
/// template before every invocation here), there's no per-call key to restore. GetSession also
/// returns the same cached session across every call here (a fixed 300-second expiry outlives any
/// single benchmark run), so this measures Encrypt/Decrypt themselves, not session refresh.
/// PayloadSize is parameterized across a small secret (64 bytes), a typical config blob (4 KiB),
/// and a larger payload (1 MiB) to show how per-call overhead versus per-byte throughput trade off.
/// </summary>
[MemoryDiagnoser]
public class AesGcmCryptoSessionBenchmarks : IDisposable
{
    private const int NonceSize = 12;
    private const int TagSize = 16;

    [Params(64, 4096, 1_048_576)]
    public int PayloadSize { get; set; }

    private ICryptoProvider _provider = null!;
    private byte[] _plaintextTemplate = null!;
    private byte[] _plaintextScratch = null!;
    private byte[] _encryptResult = null!;
    private byte[] _ciphertext = null!;
    private byte[] _decryptResult = null!;

    [GlobalSetup]
    public void GlobalSetup()
    {
        var keyWrapper = new FixedKeyWrapper(RandomNumberGenerator.GetBytes(32));
        _provider = new AesGcmCryptoProvider(keyWrapper, [.. "wrapped"u8], 300);
        _plaintextTemplate = RandomNumberGenerator.GetBytes(PayloadSize);
        _plaintextScratch = new byte[PayloadSize];
        _encryptResult = new byte[PayloadSize + NonceSize + TagSize];
        _decryptResult = new byte[PayloadSize];

        // Precompute one ciphertext to decrypt repeatedly - Decrypt doesn't zero its ciphertext
        // argument, so this buffer is safe to reuse across every Decrypt invocation.
        var plaintextForCiphertext = (byte[])_plaintextTemplate.Clone();
        _ciphertext = new byte[PayloadSize + NonceSize + TagSize];
        _provider.Encrypt(plaintextForCiphertext, _ciphertext);
    }

    [Benchmark]
    public int Encrypt()
    {
        _plaintextTemplate.CopyTo(_plaintextScratch, 0);
        return _provider.Encrypt(_plaintextScratch, _encryptResult);
    }

    [Benchmark]
    public int Decrypt()
        => _provider.Decrypt(_ciphertext, _decryptResult);

    // Reveals the same fixed key regardless of the wrapped bytes passed in - isolates this
    // benchmark from real key-wrapping/unwrapping cost, which AesGcmCryptoSessionProvider only
    // pays once anyway (see GlobalSetup's comment on session caching).
    private sealed class FixedKeyWrapper(byte[] key) : IKeyWrapper
    {
        public int Encrypt(Span<byte> plaintext, Span<byte> result) => throw new NotSupportedException();

        public int Decrypt(ReadOnlySpan<byte> wrapped, Span<byte> result)
        {
            key.CopyTo(result);
            return key.Length;
        }

        public int GenerateAndWrap(Span<byte> result) => throw new NotSupportedException();
    }

    public void Dispose()
    {
        _provider.Dispose();
    }
}
