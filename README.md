# HkdfGuard

A C# library for protecting data-at-rest encryption keys using native, platform-backed key
management (TPM2 on Linux, Secure Enclave on macOS, the Platform Crypto Provider/TPM on Windows -
see `HkdfGuard.KeyWrapping.V1`) combined with AES-GCM for the actual data encryption. Application
code works against a `KeyRing` to encrypt/decrypt strings and binary data, with key-version
tracking and purpose-scoped Additional Authenticated Data (AAD).

## Key concepts

- **No plaintext key ever touches disk or this process's memory for longer than a single
  operation.** Wrapping/unwrapping a data encryption key (DEK) is delegated entirely to the native
  KMS library for the current OS (`NativeHkdfKeyWrapperV1`) - the KEK never leaves that native
  library, and this library only ever sees the wrapped payload plus the momentarily-revealed DEK.
- **Identified by service name, not a shared master key.** A key is identified to the native KMS
  library by a service name - not by any secret this library holds itself. `KeyRingBuilder` carries this,
  along with a cache-expiry/rotation policy, fluently.
- **One `IKeyWrapper` per KEK, not per wrapped payload.** `IKeyWrapper.Decrypt` takes the wrapped
  payload as an explicit argument, so a single wrapper instance (bound only to a KEK - e.g. a
  `NativeHkdfKeyWrapperV1` for one service name) can reveal any number of different wrapped DEKs
  sharing that KEK, one per registered key file.
- **Cached, expiring, proactively-refreshed cipher sessions via `ICryptoSession`/
  `ICryptoSessionProvider`.** A revealed DEK is bound into an `ICryptoSession` once, not
  re-derived on every Encrypt/Decrypt - `ExpiresAt` (1-300 seconds) marks when it should be
  refreshed instead of reused. `ICryptoSessionProvider` owns that refresh, and does it ahead of
  time: a background timer, ticking every `expirySeconds`, reveals and builds the next session
  before the current one expires, then swaps it in and disposes the outgoing one (zeroing its
  key) - so `GetSession` almost never pays the unwrap cost itself, and only falls back to a
  synchronous refresh in the rare case a call lands in the gap right at expiry. The concrete
  session type itself (e.g. `AesGcmCryptoSession`) is an internal implementation detail - callers
  only ever see it through `ICryptoSession`, obtained from a public `ICryptoSessionProvider` (e.g.
  `AesGcmCryptoSessionProvider`).
- **Versioned, rotatable keys via `KeyRing`.** A `KeyRing` tracks any number of independently
  wrapped keys by an integer version. The highest version added automatically becomes the ring's
  `CurrentVersion` - no separate "mark as current" step, so it can never drift out of sync with
  what's actually registered.
- **Purpose-scoped protectors.** `IDataProtector` binds a `name` (purpose) to every operation as
  AAD, so a value protected for one purpose can never be decrypted under another - even using the
  same underlying key.
- **Span-based, allocation-conscious API.** Byte and char spans are used throughout; secrets are
  zeroed immediately after use and never returned as strings except for the final,
  already-encrypted, Base64-formatted output.
- **Built-in telemetry.** Every library emits `System.Diagnostics.ActivitySource` activities
  (OpenTelemetry-compatible) with exceptions recorded on failure, and an opt-in sensitive-logging
  mode that emits operation metadata (never raw key/plaintext/ciphertext bytes).

## Solution layout

| Project | Purpose |
|---|---|
| `HkdfGuard.Diagnostics` | Every library's telemetry, centralized: `HkdfGuardTelemetry` (one `ComponentTelemetry` per component - `ActivitySource`, `Meter`, `EnableSensitiveLogging`, `RecordException`, `LogSensitiveOperation`), `ActivityNames`/`AttributeNames`/`EventNames`/`MetricNames` (OpenTelemetry semantic-convention-style names, e.g. `hkdfguard.cache.add`), `CacheMetrics`, and `HkdfGuardLoggerExtensions` (`[LoggerMessage]`-generated `ILogger` extensions). No dependency on any other project in this solution - the lowest layer, designed so its naming/shape can be ported identically into a Java/Node/Python/Go implementation. |
| `HkdfGuard.Abstractions` | Interfaces and pure data types only (`IKeyWrapper`, `ICryptoSession`, `ICryptoSessionProvider`, `IDataProtectionKey`, `IDataProtector`, `IEncryptedFormatProvider`, `KeyTrackingValue`, `ArrayUtility`, `ProtectedCacheBase`). Depends only on `HkdfGuard.Diagnostics`. |
| `HkdfGuard.CryptoSession.AesGcm256` | `AesGcmCryptoSession` (internal - an `ICryptoSession`, key-bound at construction) and the public `AesGcmCryptoSessionProvider` (an `ICryptoSessionProvider` that reveals/refreshes it from an `IKeyWrapper` + wrapped bytes, and is the sole place the 1-300 second expiry range is validated - the provider only ever holds one active session at a time). Depends on `HkdfGuard.Abstractions`/`HkdfGuard.Diagnostics`; its `HkdfGuardTelemetry.CryptoSessionAesGcm256` component keeps its own independent `EnableSensitiveLogging` flag rather than sharing `Root`'s. |
| `HkdfGuard.KeyWrapping.V1` | `NativeHkdfKeyWrapperV1` (an `IKeyWrapper`) and `NativeHost`, which resolve and bind the current OS's native KMS library (Linux/.so, macOS/.dylib, Windows/.dll - see `Interop/`) to wrap and unwrap a 32-byte DEK under a service-identified KEK held entirely outside this process. |
| `HkdfGuard.DataEncryptionKey` | The application-facing API: `KeyRing`/`KeyRingBuilder`, `IDataProtector`/`DataProtector`, `KeyWrappedDataEncryptionKey`, `EphemeralDataEncryptionKey`, `PipelineDataEncryptionKey`, and the default `enc::v{version}::{base64}` wire format. |
| `HkdfGuard.DependencyInjection` | `AddKeyRing` - registers a `KeyRing` into an `IServiceCollection`, built lazily on first resolution. |
| `HkdfGuard.Options` | `HkdfGuardOptions`/`HkdfGuardOptionsValidator`/`HkdfGuardOptionsExtensions.ApplyTo` - a plain-data mirror of `KeyRingBuilder`'s configuration surface, for binding a `KeyRing`'s identity/policy/key files from configuration. |
| `HkdfGuard.Diagnostics.Test`, `HkdfGuard.Abstractions.Test`, `HkdfGuard.CryptoSession.AesGcm256.Test`, `HkdfGuard.DataEncryptionKey.Test`, `HkdfGuard.DependencyInjection.Test`, `HkdfGuard.Options.Test` | xUnit test suites, maintained at full line/branch coverage for their respective projects. |

Requires **.NET 10** (`net10.0`).

## Getting started

### 1. Wrap or reveal a DEK

`NativeHkdfKeyWrapperV1` is an `IKeyWrapper` bound to whichever native KMS library matches the
current OS (resolved once per process by `NativeHost`), identified only by a service name. Since
`Decrypt` takes the wrapped payload as an explicit argument rather than one bound at construction,
a single instance freely handles both directions, and any number of different wrapped payloads
sharing that service name:

```csharp
var wrapper = new NativeHkdfKeyWrapperV1("my-service");

// Protect a fresh 32-byte DEK under the KEK identified by "my-service":
byte[] wrapped = new byte[512]; // native library's own payload format/size
int written = wrapper.Encrypt(freshDek, wrapped);

// Later, reveal a DEK from a previously-wrapped payload for the same service:
Span<byte> dek = stackalloc byte[32];
wrapper.Decrypt(wrapped.AsSpan(0, written), dek);
```

The native ABI has no concept of Additional Authenticated Data - the 3-arg `Encrypt`/`Decrypt`
overloads only accept an empty `aad`.

### 2. Build a `KeyRing`

`KeyRingBuilder` fluently collects a service name/cache-expiry/rotation
policy, a shared `IKeyWrapper` and a session-provider factory, and any number of wrapped-DEK
files - one per version - then reads each file, mints its own `ICryptoSessionProvider`, and wires
it into a `KeyWrappedDataEncryptionKey`. `WithEphemeralKey` registers a version whose own key is
instead generated fresh in memory on first use (see `EphemeralDataEncryptionKey`) - it shares the
same `IKeyWrapper`/session-provider factory, so no extra configuration is needed for it:

```csharp
var ring = new KeyRingBuilder()
    .WithServiceName("my-service")
    .WithCachedKeyExpiry(60)   // seconds, 0-300
    .WithKeyRotationDays(90)   // 1-180
    .WithKeyWrapper(new NativeHkdfKeyWrapperV1("my-service"))
    .WithSessionProviderFactory((keyWrapper, wrapped) => new AesGcmCryptoSessionProvider(keyWrapper, wrapped, 60))
    .WithKeyFile(version: 1, pathToFile: "/path/to/wrapped-dek-v1.bin")
    .WithEphemeralKey(version: 2)
    .Build();
```

Registering additional key files at higher version numbers (e.g. during a rotation) is all that's
needed to advance `ring.CurrentVersion` - existing ciphertext tagged with older versions continues
to decrypt correctly as long as those files stay registered.

Or via `HkdfGuard.DependencyInjection`'s `AddKeyRing`, which registers the built `KeyRing` as a
singleton (built lazily, on first resolution - calling it twice keeps the first registration):

```csharp
services.AddKeyRing(builder => builder
    .WithServiceName("my-service")
    .WithKeyWrapper(new NativeHkdfKeyWrapperV1("my-service"))
    .WithSessionProviderFactory((keyWrapper, wrapped) => new AesGcmCryptoSessionProvider(keyWrapper, wrapped, 60))
    .WithKeyFile(version: 1, pathToFile: "/path/to/wrapped-dek-v1.bin")
    .Build());
```

### 3. Encrypt and decrypt

```csharp
IDataProtector protector = ring.CreateProtector("cookie-auth"); // "cookie-auth" becomes this protector's AAD

string encrypted = protector.Encrypt("secret value".AsSpan());
// e.g. "enc::v1::AbCdEf..."

Span<char> buffer = new char[protector.GetMaxDecryptedLength(encrypted.AsSpan())];
int written = protector.Decrypt(encrypted.AsSpan(), buffer);
string decrypted = new string(buffer[..written]);
```

A value encrypted by one protector name can never be decrypted by a protector created with a
different name, even from the same `KeyRing` - the name is bound in as AAD on every operation.

### Ephemeral, in-memory-only keys

For scenarios that don't need a durable, file-backed key at all, `EphemeralDataEncryptionKey`
generates and wraps a fresh DEK once, in its constructor, via `IKeyWrapper.GenerateAndWrap` - the
plaintext DEK never crosses that call's return value, and nothing here is ever written to or read
from a file. It then uses the same factory-delegate seam as `KeyRingBuilder` to bind an
`ICryptoSessionProvider` to that freshly-wrapped payload:

```csharp
IDataProtectionKey ephemeralKey = new EphemeralDataEncryptionKey(
    new NativeHkdfKeyWrapperV1("my-service"),
    (keyWrapper, wrapped) => new AesGcmCryptoSessionProvider(keyWrapper, wrapped, 60));
```

### Pipeline keys - encrypt now, wrap later

`PipelineDataEncryptionKey` is for the moment before a durable KEK even exists yet - e.g. a
provisioning pipeline that needs to encrypt secrets in-flight, then hand the same plaintext DEK to
the platform's native "initialize" CLI utility at the end of the chain, which independently
wraps/registers it against a real KEK. Unlike every other `IDataProtectionKey` here, its DEK is
never wrapped or unwrapped - it's used exactly as given (or freshly generated) via a trivial
identity `IKeyWrapper` internal to the class:

```csharp
using var pipelineKey = new PipelineDataEncryptionKey(
    (keyWrapper, wrapped) => new AesGcmCryptoSessionProvider(keyWrapper, wrapped, 60));
// or: new PipelineDataEncryptionKey(myExisting32ByteDek, sessionProviderFactory)

byte[] encrypted = pipelineKey.Encrypt("secret value"u8);

// At the end of the pipeline, hand the plaintext DEK off to be wrapped for real:
ReadOnlySpan<byte> dek = pipelineKey.AsSpan();
InitializeWithNativeCli(dek);
```

Disposing a `PipelineDataEncryptionKey` zeroes its DEK.

## Diagnostics

All telemetry lives in `HkdfGuard.Diagnostics`. `HkdfGuardTelemetry` exposes one
`ComponentTelemetry` per component (`Root`, `Cache`, `DataProtection`, `EncryptedConfiguration`,
`CryptoSessionAesGcm256`, `KeyWrapping`), each with its own `ActivitySource`/`Meter` and an
`EnableSensitiveLogging` flag - `Root`/`Cache`/`DataProtection`/`EncryptedConfiguration` share one
flag; `CryptoSessionAesGcm256` and `KeyWrapping` each keep their own, independent flag. When
enabled, operations emit a fixed-name `hkdfguard.sensitive_operation` debug event carrying only
non-sensitive metadata (lengths, versions, identifiers) as attributes - raw key, plaintext, and
ciphertext bytes are never logged, regardless of this setting.

Span, event, attribute, and metric names all follow OpenTelemetry semantic-convention style -
lowercase, dot-separated (e.g. `hkdfguard.cache.add`, attribute `hkdfguard.plaintext_length`) - see
`ActivityNames`/`AttributeNames`/`EventNames`/`MetricNames`. This naming is the part of the design
meant to translate identically into a future Java/Node/Python/Go port's own OpenTelemetry SDK.

`ProtectedCache` is the pattern class for this project's newer metrics/logging extension points:
it accepts an optional, nullable `ILogger<ProtectedCache>` (via `HkdfGuardLoggerExtensions`'
source-generated `[LoggerMessage]` methods) alongside its existing `Activity` telemetry, and
increments `CacheMetrics.Operations` (a `Counter<long>` on `HkdfGuardTelemetry.Cache.Meter`) on
every Add/AddOrUpdate. Rolling the same optional-logger/metrics pattern out to every other
component is deliberate future work, not yet done everywhere.

## Testing

Each library has a corresponding xUnit test project maintained at 100% (or documented,
justified-exception) line and branch coverage, verified via `coverlet`.
