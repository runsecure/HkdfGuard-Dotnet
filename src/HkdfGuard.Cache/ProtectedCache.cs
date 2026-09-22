using HkdfGuard.Abstractions;
using HkdfGuard.Diagnostics;
using Microsoft.Extensions.Logging;

namespace HkdfGuard.Cache;

/// <summary>
/// Default IProtectedCache. Backed by a single, already-built IDataProtectionKey - every
/// Add/AddOrUpdate encrypts through it (see ProtectedCacheBase), every Decrypt reveals
/// through it. Add uses TryAdd as its atomicity gate so a duplicate name is rejected even under
/// concurrent callers; AddOrUpdate's upsert and Decrypt's reads are otherwise lock-free, so
/// this holds up under highly concurrent access in every direction. Nothing here ever holds
/// plaintext beyond the duration of a single Add/AddOrUpdate/Decrypt call.
///
/// The pattern class for HkdfGuard.Diagnostics's metrics/logging extension points: logger is
/// optional (defaults to null, so every existing call site keeps compiling unchanged) and, when
/// supplied, receives a debug log per sensitive operation and an error log per failure alongside
/// the existing Activity/CacheMetrics.Operations telemetry.
/// </summary>
public sealed class ProtectedCache(IDataProtectionKey dataProtectionKey, ILogger<ProtectedCache>? logger = null)
    : ProtectedCacheBase(dataProtectionKey), IProtectedCache
{
    /// <inheritdoc/>
    public void Add(string name, Span<byte> plaintext)
    {
        using var activity = HkdfGuardTelemetry.Cache.ActivitySource.StartActivity(ActivityNames.Cache.Add);
        if (HkdfGuardTelemetry.Cache.EnableSensitiveLogging)
        {
            HkdfGuardTelemetry.Cache.LogSensitiveOperation(activity, ActivityNames.Cache.Add,
                (AttributeNames.Name, name), (AttributeNames.PlaintextLength, plaintext.Length));
            logger?.SensitiveOperationLogged(ActivityNames.Cache.Add, name);
        }

        try
        {
            if (!Cache.TryAdd(name, Encrypt(plaintext)))
                throw new ArgumentException($"An item with the name '{name}' has already been added.", nameof(name));

            RecordOperation(ActivityNames.Cache.Add, success: true);
        }
        catch (Exception ex)
        {
            HkdfGuardTelemetry.Cache.RecordException(activity, ex);
            logger?.OperationFailed(ActivityNames.Cache.Add, ex);
            RecordOperation(ActivityNames.Cache.Add, success: false);
            throw;
        }
    }

    /// <inheritdoc/>
    public void Add(string name, Span<char> plaintext)
    {
        using var activity = HkdfGuardTelemetry.Cache.ActivitySource.StartActivity(ActivityNames.Cache.Add);
        if (HkdfGuardTelemetry.Cache.EnableSensitiveLogging)
        {
            HkdfGuardTelemetry.Cache.LogSensitiveOperation(activity, ActivityNames.Cache.Add,
                (AttributeNames.Name, name), (AttributeNames.PlaintextLength, plaintext.Length));
            logger?.SensitiveOperationLogged(ActivityNames.Cache.Add, name);
        }

        try
        {
            if (!Cache.TryAdd(name, EncryptChars(plaintext)))
                throw new ArgumentException($"An item with the name '{name}' has already been added.", nameof(name));

            RecordOperation(ActivityNames.Cache.Add, success: true);
        }
        catch (Exception ex)
        {
            HkdfGuardTelemetry.Cache.RecordException(activity, ex);
            logger?.OperationFailed(ActivityNames.Cache.Add, ex);
            RecordOperation(ActivityNames.Cache.Add, success: false);
            throw;
        }
    }

    /// <inheritdoc/>
    public void AddOrUpdate(string name, Span<byte> plaintext)
    {
        using var activity = HkdfGuardTelemetry.Cache.ActivitySource.StartActivity(ActivityNames.Cache.AddOrUpdate);
        if (HkdfGuardTelemetry.Cache.EnableSensitiveLogging)
        {
            HkdfGuardTelemetry.Cache.LogSensitiveOperation(activity, ActivityNames.Cache.AddOrUpdate,
                (AttributeNames.Name, name), (AttributeNames.PlaintextLength, plaintext.Length));
            logger?.SensitiveOperationLogged(ActivityNames.Cache.AddOrUpdate, name);
        }

        try
        {
            Cache[name] = Encrypt(plaintext);
            RecordOperation(ActivityNames.Cache.AddOrUpdate, success: true);
        }
        catch (Exception ex)
        {
            HkdfGuardTelemetry.Cache.RecordException(activity, ex);
            logger?.OperationFailed(ActivityNames.Cache.AddOrUpdate, ex);
            RecordOperation(ActivityNames.Cache.AddOrUpdate, success: false);
            throw;
        }
    }

    /// <inheritdoc/>
    public void AddOrUpdate(string name, Span<char> plaintext)
    {
        using var activity = HkdfGuardTelemetry.Cache.ActivitySource.StartActivity(ActivityNames.Cache.AddOrUpdate);
        if (HkdfGuardTelemetry.Cache.EnableSensitiveLogging)
        {
            HkdfGuardTelemetry.Cache.LogSensitiveOperation(activity, ActivityNames.Cache.AddOrUpdate,
                (AttributeNames.Name, name), (AttributeNames.PlaintextLength, plaintext.Length));
            logger?.SensitiveOperationLogged(ActivityNames.Cache.AddOrUpdate, name);
        }

        try
        {
            Cache[name] = EncryptChars(plaintext);
            RecordOperation(ActivityNames.Cache.AddOrUpdate, success: true);
        }
        catch (Exception ex)
        {
            HkdfGuardTelemetry.Cache.RecordException(activity, ex);
            logger?.OperationFailed(ActivityNames.Cache.AddOrUpdate, ex);
            RecordOperation(ActivityNames.Cache.AddOrUpdate, success: false);
            throw;
        }
    }

    private static void RecordOperation(string operationName, bool success)
        => CacheMetrics.Operations.Add(1,
            new KeyValuePair<string, object?>(AttributeNames.OperationName, operationName),
            new KeyValuePair<string, object?>(AttributeNames.Result, success ? "success" : "error"));
}
