// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

#if NETSTANDARD2_0
#nullable enable
#endif

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using System.Diagnostics.CodeAnalysis;

#pragma warning disable IDE0130 // Namespace does not match folder structure
namespace idunno.Authentication.Basic
#pragma warning restore IDE0130 // Namespace does not match folder structure
{

    public class BasicAuthenticationFailedContext : ResultContext<BasicAuthenticationOptions>
    {
        [SuppressMessage("Style", "IDE0290:Use primary constructor", Justification = "Username is required, and required is not supported on NETSTANDARD2.0")]
        public BasicAuthenticationFailedContext(
            HttpContext context,
            AuthenticationScheme scheme,
            BasicAuthenticationOptions options)
            : base(context, scheme, options)
        {
        }

        public Exception? Exception { get; set; }
    }
}
