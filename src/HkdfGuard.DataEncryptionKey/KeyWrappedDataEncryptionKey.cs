using HkdfGuard.Abstractions;
using HkdfGuard.Diagnostics;

namespace HkdfGuard.DataEncryptionKey;

/// <summary>
/// An IDataEncryptionKey backed by one wrapped DEK payload. sessionProvider owns revealing that
/// payload's key (from a fresh unwrap, once its cached ICryptoSession expires) and performing the
/// actual data encrypt/decrypt with it - see ICryptoSessionProvider. Every operation resolves
/// GetSession fresh rather than caching the session itself, so it always uses a non-expired one.
/// </summary>
public sealed class KeyWrappedDataEncryptionKey(ICryptoProvider provider) : EncryptionKeyBase(provider);
