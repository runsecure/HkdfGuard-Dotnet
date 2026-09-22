namespace HkdfGuard.Options;

/// <summary>
/// One KeyRingBuilder.WithKeyFile registration - a version paired with the path to its wrapped
/// DEK file on disk.
/// </summary>
public sealed class KeyFileOptions
{
    public int Version { get; set; }

    public string Path { get; set; } = string.Empty;
}
