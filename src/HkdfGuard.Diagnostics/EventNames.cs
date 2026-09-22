namespace HkdfGuard.Diagnostics;

/// <summary>
/// Fixed Activity event names. Unlike the operation-specific <see cref="ActivityNames"/>, an
/// event's own name stays constant regardless of which operation raised it - the operation itself
/// is carried as the <see cref="AttributeNames.OperationName"/> attribute instead - so event names
/// stay low-cardinality and stable for dashboards/queries.
/// </summary>
public static class EventNames
{
    public const string SensitiveOperation = "hkdfguard.sensitive_operation";
}
