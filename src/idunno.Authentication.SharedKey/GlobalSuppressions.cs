// This file is used by Code Analysis to maintain SuppressMessage
// attributes that are applied to this project.
// Project-level suppressions either have no target or are given
// a specific target and scoped to a namespace, type, member, etc.

using System.Diagnostics.CodeAnalysis;

[assembly: SuppressMessage("Performance", "CA1812:Avoid uninstantiated internal classes", Justification = "Instantiated via SharedKeyAuthenticationExtensions.", Scope = "type", Target = "~T:idunno.Authentication.SharedKey.SharedKeyAuthenticationHandler")]
[assembly: SuppressMessage("Globalization", "CA1303:Do not pass literals as localized parameters", Justification = "Log messages must be a constant.", Scope = "member", Target = "~M:idunno.Authentication.SharedKey.SharedKeyAuthenticationHandler.HandleAuthenticateAsync~System.Threading.Tasks.Task{Microsoft.AspNetCore.Authentication.AuthenticateResult}")]
[assembly: SuppressMessage("Security", "CA5351:Do Not Use Broken Cryptographic Algorithms", Justification = "MD5 is part of the HTTP specification.", Scope = "member", Target = "~M:idunno.Authentication.SharedKey.SignatureValidator.CalculateBodyMd5(System.Net.Http.HttpRequestMessage)~System.Threading.Tasks.Task{System.Byte[]}")]
[assembly: SuppressMessage("Style", "IDE0090:Use 'new(...)'", Justification = "Not available in all targets.", Scope = "member", Target = "~F:idunno.Authentication.SharedKey.CanonicalizedStringBuilder.stringBuilder")]
[assembly: SuppressMessage("Usage", "CA2249:Consider using 'string.Contains' instead of 'string.IndexOf'", Justification = "Not available in all targets.", Scope = "member", Target = "~M:idunno.Authentication.SharedKey.SharedKeyAuthentication.TryParse(System.String,System.String@,System.String@)~System.Boolean")]
[assembly: SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Wrapping all encoded failures to return generic error", Scope = "member", Target = "~M:idunno.Authentication.SharedKey.SharedKeyAuthenticationHandler.HandleAuthenticateAsync~System.Threading.Tasks.Task{Microsoft.AspNetCore.Authentication.AuthenticateResult}")]
[assembly: SuppressMessage("Security", "CA5351:Do Not Use Broken Cryptographic Algorithms", Justification = "MD5 is part of the HTTP specification", Scope = "member", Target = "~M:idunno.Authentication.SharedKey.SharedKeyAuthenticationHandler.HandleAuthenticateAsync~System.Threading.Tasks.Task{Microsoft.AspNetCore.Authentication.AuthenticateResult}")]
[assembly: SuppressMessage("Globalization", "CA1303:Do not pass literals as localized parameters", Justification = "Exception messages will not be globalized", Scope = "member", Target = "~M:idunno.Authentication.SharedKey.CanonicalizationHelpers.CanonicalizeHeaders(System.Net.Http.HttpRequestMessage)~System.String")]
