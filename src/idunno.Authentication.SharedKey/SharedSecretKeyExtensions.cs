// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using Microsoft.AspNetCore.Authentication;

using idunno.Authentication.SharedKey;

namespace Microsoft.AspNetCore.Builder
{
    public static class SharedKeyExtensions
    {
        public static AuthenticationBuilder AddSharedKey(this AuthenticationBuilder builder)
            => builder.AddSharedKey(SharedKeyAuthenticationDefaults.AuthenticationScheme);

        public static AuthenticationBuilder AddSharedKey(this AuthenticationBuilder builder, string authenticationScheme)
            => builder.AddSharedKey(authenticationScheme, configureOptions: null);

        public static AuthenticationBuilder AddSharedKey(this AuthenticationBuilder builder, Action<SharedKeyAuthenticationOptions> configureOptions)
            => builder.AddSharedKey(SharedKeyAuthenticationDefaults.AuthenticationScheme, configureOptions);

        public static AuthenticationBuilder AddSharedKey(
            this AuthenticationBuilder builder,
            string authenticationScheme,
            Action<SharedKeyAuthenticationOptions> configureOptions)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            return builder.AddScheme<SharedKeyAuthenticationOptions, SharedKeyAuthenticationHandler>(authenticationScheme, configureOptions);
        }
    }
}
