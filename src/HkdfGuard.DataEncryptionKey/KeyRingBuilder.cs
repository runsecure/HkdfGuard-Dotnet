using HkdfGuard.Abstractions;
using HkdfGuard.DataEncryptionKey.FormatProvider;

namespace HkdfGuard.DataEncryptionKey;

/// <summary>
/// Builds a KeyRing from wrapped-DEK files on disk, suitable for registering as a singleton in a
/// DI container at startup. There is one IKeyWrapper shared by every registered file - it's bound
/// only to a KEK (e.g. NativeHkdfKeyWrapperV1's service name), not to any one wrapped payload, so
/// it can reveal any number of different files' DEKs (see IKeyWrapper). Each registered file gets
/// its own ICryptoSessionProvider (minted by sessionProviderFactory, bound to that file's own
/// wrapped bytes) and becomes its own KeyWrappedDataEncryptionKey. WithEphemeralKey registers a
/// version whose own key material is instead generated fresh in memory on first use (see
/// EphemeralDataEncryptionKey) - it shares the same IKeyWrapper/sessionProviderFactory, so no
/// extra configuration is needed for it.
/// ServiceName/CachedKeyExpiry/KeyRotationDays describe this ring's key identity/policy - they're
/// carried on the builder for callers to read back, but are not consumed by Build itself, since
/// IKeyWrapper already knows what KEK it's bound to.
/// </summary>
public sealed class KeyRingBuilder
{
    private readonly SortedDictionary<int, string> _keyFiles = [];
    private readonly List<int> _ephemeralVersions = [];
    private IKeyWrapper? _keyWrapper;
    private ICryptoProviderFactory? _cryptoProviderFactory;
    private IEncryptedFormatProvider _formatProvider = new DefaultFormatProvider();

    public string? ServiceName { get; private set; }
    public int? CachedKeyExpiry { get; private set; }
    public int? KeyRotationDays { get; private set; }

    /// <summary>
    /// The service name identifying this ring's KEK to the native KMS library.
    /// </summary>
    public KeyRingBuilder WithServiceName(string serviceName)
    {
        ServiceName = serviceName;
        return this;
    }

    /// <summary>
    /// How many seconds a revealed key may be cached in memory before it must be re-derived.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">cachedKeyExpiry is not between 0 and 300</exception>
    public KeyRingBuilder WithCachedKeyExpiry(int cachedKeyExpiry)
    {
        if (cachedKeyExpiry is < 0 or > 300)
            throw new ArgumentOutOfRangeException(nameof(cachedKeyExpiry), cachedKeyExpiry, "CachedKeyExpiry must be between 0 and 300 seconds.");

        CachedKeyExpiry = cachedKeyExpiry;
        return this;
    }

    /// <summary>
    /// How many days may pass before this ring's key must be rotated.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">keyRotationDays is not between 1 and 180</exception>
    public KeyRingBuilder WithKeyRotationDays(int keyRotationDays)
    {
        if (keyRotationDays is < 1 or > 180)
            throw new ArgumentOutOfRangeException(nameof(keyRotationDays), keyRotationDays, "KeyRotationDays must be between 1 and 180 days.");

        KeyRotationDays = keyRotationDays;
        return this;
    }

    /// <summary>
    /// Supplies the IKeyWrapper shared by every registered key file when Build runs.
    /// </summary>
    public KeyRingBuilder WithKeyWrapper(IKeyWrapper keyWrapper)
    {
        _keyWrapper = keyWrapper;
        return this;
    }

    /// <summary>
    /// Supplies the factory used to build each key file's own ICryptoSessionProvider, called once
    /// per registered file with the shared IKeyWrapper and that file's own wrapped bytes - e.g.
    /// <c>(kw, wrapped) => new AesGcmCryptoSessionProvider(kw, wrapped, 60)</c>.
    /// </summary>
    public KeyRingBuilder WithCryptoProviderFactory(ICryptoProviderFactory cryptoProviderFactory)
    {
        _cryptoProviderFactory = cryptoProviderFactory;
        return this;
    }

    /// <summary>
    /// Overrides the IEncryptedFormatProvider the built KeyRing uses for CreateProtector.
    /// Defaults to DefaultFormatProvider.
    /// </summary>
    public KeyRingBuilder WithFormatProvider(IEncryptedFormatProvider formatProvider)
    {
        _formatProvider = formatProvider;
        return this;
    }

    /// <summary>
    /// Registers a version whose wrapped DEK will be read from pathToFile when Build runs. The
    /// highest version registered across every WithKeyFile call intrinsically becomes the built
    /// KeyRing's CurrentVersion.
    /// </summary>
    /// <param name="version">The KeyRing version to register this key under</param>
    /// <param name="pathToFile">Path to this version's wrapped DEK file</param>
    public KeyRingBuilder WithKeyFile(int version, string pathToFile)
    {
        _keyFiles.Add(version, pathToFile);
        return this;
    }

    /// <summary>
    /// Registers a version whose own key material is generated fresh in memory the first time
    /// it's used, and never written to or read from disk (see EphemeralDataEncryptionKey). The
    /// highest version registered across every WithKeyFile/WithEphemeralKey call intrinsically
    /// becomes the built KeyRing's CurrentVersion.
    /// </summary>
    /// <param name="version">The KeyRing version to register this key under</param>
    public KeyRingBuilder WithEphemeralKey(int version)
    {
        _ephemeralVersions.Add(version);
        return this;
    }

    /// <summary>
    /// Reads each registered key file's wrapped bytes, mints each registered ephemeral key, and
    /// returns a populated KeyRing.
    /// </summary>
    /// <exception cref="InvalidOperationException">No key wrapper, no session provider factory, or no key files/ephemeral keys were configured</exception>
    public KeyRing Build()
    {
        if (_keyWrapper is null)
            throw new InvalidOperationException("A key wrapper is required - call WithKeyWrapper first.");

        if (_cryptoProviderFactory is null)
            throw new InvalidOperationException("A session provider factory is required - call WithCryptoProviderFactory first.");

        if (_keyFiles.Count == 0 && _ephemeralVersions.Count == 0)
            throw new InvalidOperationException("At least one key file or ephemeral key is required - call WithKeyFile or WithEphemeralKey first.");

        if (CachedKeyExpiry is null)
            throw new InvalidOperationException("A cached key expiry is required - call WithCachedKeyExpiry first.");

        var ring = new KeyRing(_formatProvider);
        foreach (var (version, path) in _keyFiles)
        {
            var wrapped = File.ReadAllBytes(path);
            var sessionProvider = _cryptoProviderFactory.Create(_keyWrapper, wrapped, CachedKeyExpiry.Value);
            ring.Add(version, new KeyWrappedDataEncryptionKey(sessionProvider));
        }

        foreach (var version in _ephemeralVersions)
        {
            var sessionProvider = _cryptoProviderFactory.CreateEphemeral(_keyWrapper, CachedKeyExpiry.Value);
            ring.Add(version, new KeyWrappedDataEncryptionKey(sessionProvider));
        }

        return ring;
    }
}
