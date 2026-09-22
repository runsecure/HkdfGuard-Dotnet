using Microsoft.Extensions.Options;

namespace HkdfGuard.Options;

/// <summary>
/// Validates an HkdfGuardOptions instance against the same constraints KeyRingBuilder itself
/// enforces (CachedKeyExpiry 0-300, KeyRotationDays 1-180, at least one key source), plus what
/// ApplyTo needs to hold before it ever touches a KeyRingBuilder - a non-empty ServiceName, every
/// KeyFile having a path, and version numbers that don't collide across KeyFiles/EphemeralKeys
/// (KeyRing.Add throws on a duplicate version at Build time; catching it here up front gives a
/// much clearer failure, at options-bind time, than deep inside Build).
/// </summary>
public sealed class HkdfGuardOptionsValidator : IValidateOptions<HkdfGuardOptions>
{
    public ValidateOptionsResult Validate(string? name, HkdfGuardOptions options)
    {
        var failures = new List<string>();

        if (string.IsNullOrWhiteSpace(options.ServiceName))
            failures.Add("ServiceName is required.");

        if (options.CachedKeyExpiry is < 0 or > 300)
            failures.Add("CachedKeyExpiry must be between 0 and 300 seconds.");

        if (options.KeyRotationDays is < 1 or > 180)
            failures.Add("KeyRotationDays must be between 1 and 180 days.");

        if (options.KeyFiles.Count == 0 && options.EphemeralKeys.Count == 0)
            failures.Add("At least one key file or ephemeral key is required.");

        // ReSharper disable once ForeachCanBeConvertedToQueryUsingAnotherGetEnumerator
        foreach (var keyFile in options.KeyFiles)
        {
            if (string.IsNullOrWhiteSpace(keyFile.Path))
                failures.Add($"KeyFiles version {keyFile.Version} is missing a path.");
        }

        var duplicateVersions = options.KeyFiles.Select(k => k.Version)
            .Concat(options.EphemeralKeys)
            .GroupBy(version => version)
            .Where(group => group.Count() > 1)
            .Select(group => group.Key);

        foreach (var version in duplicateVersions)
            failures.Add($"Version {version} is registered more than once across KeyFiles/EphemeralKeys.");

        return failures.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(failures);
    }
}
