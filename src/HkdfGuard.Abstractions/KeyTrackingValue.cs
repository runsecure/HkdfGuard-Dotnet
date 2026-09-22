namespace HkdfGuard.Abstractions;

public class KeyTrackingValue
{
    public int KeyVersion { get; init; }
    public byte[] Value { get; init; }
}
