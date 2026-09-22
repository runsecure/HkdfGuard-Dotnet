using Microsoft.Extensions.Logging;

namespace HkdfGuard.Diagnostics;

/// <summary>
/// Source-generated ILogger extension methods, shared by every component that chooses to accept
/// an optional ILogger (e.g. ProtectedCache's constructor). Mirrors LogSensitiveOperation/
/// RecordException's gating: SensitiveOperationLogged is only worth calling when
/// ComponentTelemetry.EnableSensitiveLogging is set, while OperationFailed is unconditional -
/// failures are always worth logging.
/// </summary>
public static partial class HkdfGuardLoggerExtensions
{
    [LoggerMessage(EventId = 1, Level = LogLevel.Debug, Message = "{OperationName} completed for {Name}.")]
    public static partial void SensitiveOperationLogged(this ILogger logger, string operationName, string? name);

    [LoggerMessage(EventId = 2, Level = LogLevel.Error, Message = "{OperationName} failed.")]
    public static partial void OperationFailed(this ILogger logger, string operationName, Exception exception);
}
