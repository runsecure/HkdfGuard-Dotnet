using HkdfGuard.Abstractions;
using HkdfGuard.CryptoSession.AesGcm256.Diagnostics;

namespace HkdfGuard.CryptoSession.AesGcm256;

/// <summary>
/// Tracks one cached AesGcmCryptoSession, bound to a single wrapped DEK. A background timer,
/// ticking every expirySeconds, proactively reveals the DEK fresh (via
/// keyWrapper.Decrypt(wrapped, ...)) and builds the next AesGcmCryptoSession before the current
/// one expires, then swaps it in and disposes the outgoing one (zeroing its key) - so GetSession
/// itself almost never pays the unwrap cost or observes an expired session. GetSession still
/// double-checks and refreshes synchronously on the rare chance a call lands in the (sub-
/// millisecond) gap between expiry and the timer's next tick. Thread-safe: concurrent refreshes
/// (background or foreground) never race to unwrap/swap the same session twice.
/// </summary>
public sealed class AesGcmCryptoSessionProvider : ICryptoSessionProvider
{
    private const int KeyLength = 32;

    private readonly IKeyWrapper _keyWrapper;
    private readonly byte[] _wrapped;
    private readonly int _expirySeconds;
    private readonly Lock _gate = new();
    private readonly Timer _refreshTimer;

    private ICryptoSession? _current;

    /// <param name="keyWrapper">Reveals wrapped's DEK - see IKeyWrapper.Decrypt.</param>
    /// <param name="wrapped">The wrapped DEK payload this provider's sessions decrypt.</param>
    /// <param name="expirySeconds">How long each refreshed session stays valid for, in the range
    /// 1-300. Also the background refresh interval: a fresh session is unwrapped this often,
    /// ahead of the current one's expiry. This provider holds only one active session at a time,
    /// so this is the sole place that range is enforced - AesGcmCryptoSession itself no longer
    /// validates it.</param>
    /// <exception cref="ArgumentOutOfRangeException">expirySeconds is not between 1 and 300</exception>
    public AesGcmCryptoSessionProvider(IKeyWrapper keyWrapper, byte[] wrapped, int expirySeconds)
    {
        if (expirySeconds is < 1 or > 300)
            throw new ArgumentOutOfRangeException(nameof(expirySeconds), expirySeconds, "ExpirySeconds must be between 1 and 300.");

        _keyWrapper = keyWrapper;
        _wrapped = wrapped;
        _expirySeconds = expirySeconds;

        Refresh();

        var period = TimeSpan.FromSeconds(expirySeconds);
        _refreshTimer = new Timer(_ => BackgroundRefresh(), null, period, period);
    }

    /// <inheritdoc/>
    public ICryptoSession GetSession()
    {
        lock (_gate)
        {
            if (_current is not null && _current.ExpiresAt > DateTimeOffset.UtcNow)
                return _current;

            Refresh();
            return _current!;
        }
    }

    // The timer callback runs on a thread-pool thread with no caller to propagate a failure to -
    // an exception escaping it would tear down the process. Swallow (after recording) instead,
    // and leave _current as-is: GetSession's own expiry check/refresh remains the fallback, and
    // correctly surfaces the failure to whichever caller next needs a session.
    private void BackgroundRefresh()
    {
        using var activity = AesGcm256Diagnostics.ActivitySource.StartActivity("AesGcmCryptoSessionProvider.BackgroundRefresh");
        try
        {
            Refresh();
        }
        catch (Exception ex)
        {
            AesGcm256Diagnostics.RecordException(activity, ex);
        }
    }

    private void Refresh()
    {
        lock (_gate)
        {
            var key = new byte[KeyLength];
            _keyWrapper.Decrypt(_wrapped, key);
            var fresh = new AesGcmCryptoSession(key, _expirySeconds);

            var outgoing = _current;
            _current = fresh;
            outgoing?.Dispose();
        }
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        _refreshTimer.Dispose();

        lock (_gate)
        {
            _current?.Dispose();
            _current = null;
        }
    }
}
