using HkdfGuard.DataEncryptionKey.Utilities;
using HkdfGuard.Abstractions;
using HkdfGuard.Diagnostics;

namespace HkdfGuard.DataEncryptionKey.FormatProvider;

public class DefaultFormatProvider : IEncryptedFormatProvider
{
    private const string EncPrefix = "enc";
    private const string Delimiter = "::";
    private const string VersionPrefix = "v";

    public string Format(KeyTrackingValue value)
    {
        using var activity = HkdfGuardTelemetry.DataProtection.ActivitySource.StartActivity(ActivityNames.DataProtection.FormatProviderFormat);
        if (HkdfGuardTelemetry.DataProtection.EnableSensitiveLogging)
            HkdfGuardTelemetry.DataProtection.LogSensitiveOperation(activity, ActivityNames.DataProtection.FormatProviderFormat,
                (AttributeNames.KeyVersion, value.KeyVersion), (AttributeNames.ValueLength, value.Value.Length));

        try
        {
            var base64 = Base64ConversionUtility.ToBase64String(value.Value);
            return $"{EncPrefix}{Delimiter}{VersionPrefix}{value.KeyVersion}{Delimiter}{base64}";
        }
        catch (Exception ex)
        {
            ComponentTelemetry.RecordException(activity, ex);
            throw;
        }
    }

    public KeyTrackingValue Parse(ReadOnlySpan<char> encrypted)
    {
        using var activity = HkdfGuardTelemetry.DataProtection.ActivitySource.StartActivity(ActivityNames.DataProtection.FormatProviderParse);
        if (HkdfGuardTelemetry.DataProtection.EnableSensitiveLogging)
            HkdfGuardTelemetry.DataProtection.LogSensitiveOperation(activity, ActivityNames.DataProtection.FormatProviderParse,
                (AttributeNames.EncryptedLength, encrypted.Length));

        try
        {
            if (!TryParseSegments(encrypted, out var version, out var base64))
                throw new FormatException(
                    $"Invalid encrypted format. Expected '{EncPrefix}{Delimiter}{VersionPrefix}<version>{Delimiter}<base64>'.");

            if (!Base64ConversionUtility.IsBase64(base64))
                throw new FormatException("Encrypted value is not valid base64.");

            var value = new byte[Base64ConversionUtility.GetBinaryLength(base64)];
            Base64ConversionUtility.FromBase64(base64, value);

            return new KeyTrackingValue
            {
                KeyVersion = version,
                Value = value
            };
        }
        catch (Exception ex)
        {
            ComponentTelemetry.RecordException(activity, ex);
            throw;
        }
    }

    /// <inheritdoc/>
    public int GetMaxDecryptedLength(ReadOnlySpan<char> encrypted)
    {
        using var activity = HkdfGuardTelemetry.DataProtection.ActivitySource.StartActivity(ActivityNames.DataProtection.FormatProviderGetMaxDecryptedLength);
        if (HkdfGuardTelemetry.DataProtection.EnableSensitiveLogging)
            HkdfGuardTelemetry.DataProtection.LogSensitiveOperation(activity, ActivityNames.DataProtection.FormatProviderGetMaxDecryptedLength,
                (AttributeNames.EncryptedLength, encrypted.Length));

        try
        {
            if (!TryParseSegments(encrypted, out _, out var base64))
                throw new FormatException(
                    $"Invalid encrypted format. Expected '{EncPrefix}{Delimiter}{VersionPrefix}<version>{Delimiter}<base64>'.");

            return Base64ConversionUtility.IsBase64(base64)
                ? Base64ConversionUtility.GetBinaryLength(base64)
                : throw new FormatException("Encrypted value is not valid base64.");
        }
        catch (Exception ex)
        {
            ComponentTelemetry.RecordException(activity, ex);
            throw;
        }
    }

    // Shared by Parse and GetMaxDecryptedLength so both agree on exactly what counts as
    // well-formed - only GetMaxDecryptedLength skips the actual Base64 decode/allocation.
    private static bool TryParseSegments(ReadOnlySpan<char> encrypted, out int version, out ReadOnlySpan<char> base64)
    {
        version = 0;
        base64 = default;

        var delimiter = Delimiter.AsSpan();

        var firstDelimiterIndex = encrypted.IndexOf(delimiter);
        if (firstDelimiterIndex < 0)
            return false;

        var afterPrefix = encrypted[(firstDelimiterIndex + delimiter.Length)..];
        var secondDelimiterIndex = afterPrefix.IndexOf(delimiter);
        if (secondDelimiterIndex < 0)
            return false;

        var prefix = encrypted[..firstDelimiterIndex];
        var versionSegment = afterPrefix[..secondDelimiterIndex];
        var base64Segment = afterPrefix[(secondDelimiterIndex + delimiter.Length)..];

        if (!prefix.SequenceEqual(EncPrefix) || !versionSegment.StartsWith(VersionPrefix))
            return false;

        if (!int.TryParse(versionSegment[VersionPrefix.Length..], out version))
            return false;

        base64 = base64Segment;
        return true;
    }
}
