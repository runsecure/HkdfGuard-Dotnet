using HkdfGuard.Abstractions;
using HkdfGuard.Diagnostics;

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
public sealed class AesGcmCryptoProvider : ICryptoProvider
{
    private const int KeyLength = 32;
    private const int ExtraAllocationLength = AesGcmCryptoSession.NonceSize + AesGcmCryptoSession.TagSize;
    
    private readonly IKeyWrapper _keyWrapper;
    private readonly byte[] _wrapped;
    private readonly int _expirySeconds;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task? _refreshTask;
    private readonly Lock _gate = new();
    private AesGcmCryptoSession? _current;

    /// <param name="keyWrapper">Reveals wrapped's DEK - see IKeyWrapper.Decrypt.</param>
    /// <param name="wrapped">The wrapped DEK payload this provider's sessions decrypt.</param>
    /// <param name="expirySeconds">How long each refreshed session stays valid for, in the range
    /// 1-300. Also the background refresh interval: a fresh session is unwrapped this often,
    /// ahead of the current one's expiry. This provider holds only one active session at a time,
    /// so this is the sole place that range is enforced - AesGcmCryptoSession itself no longer
    /// validates it.</param>
    /// <exception cref="ArgumentOutOfRangeException">expirySeconds is not between 1 and 300</exception>
    public AesGcmCryptoProvider(IKeyWrapper keyWrapper, byte[] wrapped, int expirySeconds)
    {
        if (expirySeconds is < 1 or > 300)
            throw new ArgumentOutOfRangeException(nameof(expirySeconds), expirySeconds, "ExpirySeconds must be between 1 and 300.");

        _keyWrapper = keyWrapper;
        _wrapped = wrapped;
        _expirySeconds = expirySeconds;

        Refresh();

        _refreshTask = RunRefreshLoopAsync(_cts.Token);
    }

    internal AesGcmCryptoProvider(IKeyWrapper keyWrapper, byte[] notWrapped)
    {
        _keyWrapper = keyWrapper;
        _wrapped = notWrapped;
        _expirySeconds = 7200;
        _current = new  AesGcmCryptoSession(notWrapped);
        _refreshTask = null;
    }
    
    public int Encrypt(Span<byte> plaintext, Span<byte> result)
    {
        var session = _current;
        ObjectDisposedException.ThrowIf(session is null, this);
        return session.Encrypt(plaintext, ReadOnlySpan<byte>.Empty, result);
    }

    public int Encrypt(Span<byte> plaintext, ReadOnlySpan<byte> aad, Span<byte> result)
    {
        var session = _current;
        ObjectDisposedException.ThrowIf(session is null, this);
        return session.Encrypt(plaintext, aad, result);
    }

    public int Decrypt(ReadOnlySpan<byte> ciphertext, Span<byte> result)
    {
        var session = _current;
        ObjectDisposedException.ThrowIf(session is null, this);
        return session.Decrypt(ciphertext, ReadOnlySpan<byte>.Empty, result);
    }

    public int Decrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> aad, Span<byte> result)
    {
        var session = _current;
        ObjectDisposedException.ThrowIf(session is null, this);
        return session.Decrypt(ciphertext, aad, result);
    }

    public int GetEncryptedAllocationLength(int length)
        => length + ExtraAllocationLength;

    public int GetDecryptedAllocationLength(int length)
        => length - ExtraAllocationLength;

    private void Refresh()
    {
        lock (_gate)
        {
            var key = new byte[KeyLength];
            _keyWrapper.Decrypt(_wrapped, key);
            var fresh = new AesGcmCryptoSession(key);

            var outgoing = Interlocked.Exchange(ref _current, fresh);
            outgoing?.Dispose();
        }
    }
    
    private async Task RunRefreshLoopAsync(
        CancellationToken cancellationToken)
    {
        using var timer =
            new PeriodicTimer(TimeSpan.FromSeconds(_expirySeconds));

        try
        {
            while (await timer.WaitForNextTickAsync(cancellationToken))
            {
                using var activity =
                    HkdfGuardTelemetry.CryptoSessionAesGcm256
                        .ActivitySource
                        .StartActivity(
                            ActivityNames.CryptoSessionAesGcm256
                                .BackgroundRefresh);

                try
                {
                    Refresh();
                }
                catch (Exception ex)
                {
                    ComponentTelemetry
                        .RecordException(activity, ex);
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Normal shutdown
        }
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        _cts.Cancel();
        ArrayUtility.ZeroMemory(_wrapped);
        
        try
        {
            _refreshTask?.Wait();
        }
        catch (AggregateException ex)
            when (ex.InnerException is OperationCanceledException)
        {
        }

        _cts.Dispose();

        lock (_gate)
        {
            var outgoing = Interlocked.Exchange(ref _current, null);
            outgoing?.Dispose();
        }
    }
}
