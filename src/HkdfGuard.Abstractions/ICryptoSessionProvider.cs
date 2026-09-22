namespace HkdfGuard.Abstractions;

/// <summary>
/// Tracks a single cached ICryptoSession, refreshing it (from a fresh key reveal/unwrap) once it
/// expires, and disposing the outgoing session as it does. Callers should call GetSession on
/// every operation rather than caching the returned ICryptoSession themselves, so they always see
/// a non-expired one.
/// </summary>
public interface ICryptoSessionProvider : IDisposable
{
    /// <summary>
    /// Returns the current, non-expired ICryptoSession, refreshing it first if the previously
    /// cached one has expired (or none has been created yet).
    /// </summary>
    public ICryptoSession GetSession();
}
