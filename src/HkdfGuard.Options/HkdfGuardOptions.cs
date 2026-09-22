namespace HkdfGuard.Options;

/// <summary>
/// Plain-data mirror of the configuration surface KeyRingBuilder itself exposes - ServiceName,
/// CachedKeyExpiry, KeyRotationDays, registered key files, and registered ephemeral keys. It
/// carries no behavior: the IKeyWrapper, session-provider factory, and IEncryptedFormatProvider a
/// real KeyRing needs still come from the caller via KeyRingBuilder directly - see
/// HkdfGuardOptionsExtensions.ApplyTo, which copies this data onto a KeyRingBuilder the caller
/// finishes and Builds themselves.
/// </summary>
public sealed class HkdfGuardOptions
{
    /// <summary>
    /// The service name identifying this ring's KEK to the native KMS library.
    /// </summary>
    public string? ServiceName { get; set; }

    /// <summary>
    /// How many seconds a revealed key may be cached in memory before it must be re-derived.
    /// </summary>
    public int? CachedKeyExpiry { get; set; }

    /// <summary>
    /// How many days may pass before this ring's key must be rotated.
    /// </summary>
    public int? KeyRotationDays { get; set; }

    /// <summary>
    /// Versions whose wrapped DEK is read from a file on disk.
    /// </summary>
    public List<KeyFileOptions> KeyFiles { get; set; } = [];

    /// <summary>
    /// Versions whose key material is generated fresh in memory on first use and never persisted.
    /// </summary>
    public List<int> EphemeralKeys { get; set; } = [];
}
