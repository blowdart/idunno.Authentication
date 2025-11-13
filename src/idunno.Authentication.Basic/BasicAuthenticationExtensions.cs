// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

#if NETSTANDARD2_0
#nullable enable
#endif

using Microsoft.AspNetCore.Authentication;

using idunno.Authentication.Basic;

#pragma warning disable IDE0130 // Namespace does not match folder structure
namespace Microsoft.AspNetCore.Builder
#pragma warning restore IDE0130 // Namespace does not match folder structure
{
    /// <summary>
    /// Extension methods to add Basic authentication capabilities to an HTTP application pipeline.
    /// </summary>
    public static class BasicAuthenticationAppBuilderExtensions
    {
        public static AuthenticationBuilder AddBasic(this AuthenticationBuilder builder)
            => builder.AddBasic(BasicAuthenticationDefaults.AuthenticationScheme);

        public static AuthenticationBuilder AddBasic(this AuthenticationBuilder builder, string authenticationScheme)
            => builder.AddBasic(authenticationScheme, configureOptions: null);

        public static AuthenticationBuilder AddBasic(this AuthenticationBuilder builder, Action<BasicAuthenticationOptions>? configureOptions)
            => builder.AddBasic(BasicAuthenticationDefaults.AuthenticationScheme, configureOptions);

        public static AuthenticationBuilder AddBasic(
            this AuthenticationBuilder builder,
            string authenticationScheme,
            Action<BasicAuthenticationOptions>? configureOptions)
        {
            return builder == null
                ? throw new ArgumentNullException(nameof(builder))
                : builder.AddScheme<BasicAuthenticationOptions, BasicAuthenticationHandler>(authenticationScheme, configureOptions);
        }
    }
}


