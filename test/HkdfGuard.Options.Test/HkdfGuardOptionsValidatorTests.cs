namespace HkdfGuard.Options.Test;

public class HkdfGuardOptionsValidatorTests
{
    private static HkdfGuardOptions ValidOptions()
        => new()
        {
            ServiceName = "my-service",
            CachedKeyExpiry = 60,
            KeyRotationDays = 90,
            EphemeralKeys = [1],
        };

    [Fact]
    public void Validate_ValidOptions_Succeeds()
    {
        var result = new HkdfGuardOptionsValidator().Validate(null, ValidOptions());

        Assert.True(result.Succeeded);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Validate_MissingServiceName_Fails(string? serviceName)
    {
        var options = ValidOptions();
        options.ServiceName = serviceName;

        var result = new HkdfGuardOptionsValidator().Validate(null, options);

        Assert.False(result.Succeeded);
        Assert.Contains(result.Failures!, f => f.Contains("ServiceName"));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(301)]
    public void Validate_CachedKeyExpiryOutOfRange_Fails(int cachedKeyExpiry)
    {
        var options = ValidOptions();
        options.CachedKeyExpiry = cachedKeyExpiry;

        var result = new HkdfGuardOptionsValidator().Validate(null, options);

        Assert.False(result.Succeeded);
        Assert.Contains(result.Failures!, f => f.Contains("CachedKeyExpiry"));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(300)]
    public void Validate_CachedKeyExpiryWithinRange_Succeeds(int cachedKeyExpiry)
    {
        var options = ValidOptions();
        options.CachedKeyExpiry = cachedKeyExpiry;

        var result = new HkdfGuardOptionsValidator().Validate(null, options);

        Assert.True(result.Succeeded);
    }

    [Fact]
    public void Validate_CachedKeyExpiryUnset_Succeeds()
    {
        var options = ValidOptions();
        options.CachedKeyExpiry = null;

        var result = new HkdfGuardOptionsValidator().Validate(null, options);

        Assert.True(result.Succeeded);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(181)]
    public void Validate_KeyRotationDaysOutOfRange_Fails(int keyRotationDays)
    {
        var options = ValidOptions();
        options.KeyRotationDays = keyRotationDays;

        var result = new HkdfGuardOptionsValidator().Validate(null, options);

        Assert.False(result.Succeeded);
        Assert.Contains(result.Failures!, f => f.Contains("KeyRotationDays"));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(180)]
    public void Validate_KeyRotationDaysWithinRange_Succeeds(int keyRotationDays)
    {
        var options = ValidOptions();
        options.KeyRotationDays = keyRotationDays;

        var result = new HkdfGuardOptionsValidator().Validate(null, options);

        Assert.True(result.Succeeded);
    }

    [Fact]
    public void Validate_KeyRotationDaysUnset_Succeeds()
    {
        var options = ValidOptions();
        options.KeyRotationDays = null;

        var result = new HkdfGuardOptionsValidator().Validate(null, options);

        Assert.True(result.Succeeded);
    }

    [Fact]
    public void Validate_NoKeyFilesOrEphemeralKeys_Fails()
    {
        var options = ValidOptions();
        options.EphemeralKeys = [];

        var result = new HkdfGuardOptionsValidator().Validate(null, options);

        Assert.False(result.Succeeded);
        Assert.Contains(result.Failures!, f => f.Contains("key file or ephemeral key"));
    }

    [Fact]
    public void Validate_KeyFileWithoutPath_Fails()
    {
        var options = ValidOptions();
        options.EphemeralKeys = [];
        options.KeyFiles = [new KeyFileOptions { Version = 1, Path = "" }];

        var result = new HkdfGuardOptionsValidator().Validate(null, options);

        Assert.False(result.Succeeded);
        Assert.Contains(result.Failures!, f => f.Contains("missing a path"));
    }

    [Fact]
    public void Validate_DuplicateVersionAcrossKeyFilesAndEphemeralKeys_Fails()
    {
        var options = ValidOptions();
        options.EphemeralKeys = [1];
        options.KeyFiles = [new KeyFileOptions { Version = 1, Path = "/tmp/dek.bin" }];

        var result = new HkdfGuardOptionsValidator().Validate(null, options);

        Assert.False(result.Succeeded);
        Assert.Contains(result.Failures!, f => f.Contains("more than once"));
    }

    [Fact]
    public void Validate_UniqueVersionsAcrossKeyFilesAndEphemeralKeys_Succeeds()
    {
        var options = ValidOptions();
        options.EphemeralKeys = [2];
        options.KeyFiles = [new KeyFileOptions { Version = 1, Path = "/tmp/dek.bin" }];

        var result = new HkdfGuardOptionsValidator().Validate(null, options);

        Assert.True(result.Succeeded);
    }
}
