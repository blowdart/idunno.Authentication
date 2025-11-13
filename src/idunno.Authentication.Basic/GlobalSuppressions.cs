// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

// This file is used by Code Analysis to maintain SuppressMessage
// attributes that are applied to this project.
// Project-level suppressions either have no target or are given
// a specific target and scoped to a namespace, type, member, etc.

using System.Diagnostics.CodeAnalysis;

[assembly: SuppressMessage("Globalization", "CA1303:Do not pass literals as localized parameters", Justification = "Error messages are not localized", Scope = "member", Target = "~M:idunno.Authentication.Basic.BasicAuthenticationHandler.HandleAuthenticateAsync~System.Threading.Tasks.Task{Microsoft.AspNetCore.Authentication.AuthenticateResult}")]
[assembly: SuppressMessage("Globalization", "CA1303:Do not pass literals as localized parameters", Justification = "Error messages are not localized", Scope = "member", Target = "~P:idunno.Authentication.Basic.BasicAuthenticationOptions.Realm")]
[assembly: SuppressMessage("Globalization", "CA1303:Do not pass literals as localized parameters", Justification = "Error messages are not localized", Scope = "member", Target = "~M:idunno.Authentication.Basic.BasicAuthenticationHandler.HandleChallengeAsync(Microsoft.AspNetCore.Authentication.AuthenticationProperties)~System.Threading.Tasks.Task")]
