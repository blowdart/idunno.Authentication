// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace idunno.Authentication.SharedKey
{
    public class SharedKeyAuthenticationFailedContext : ResultContext<SharedKeyAuthenticationOptions>
    {
        /// <summary>
        /// Creates a new instance of <see cref="SharedKeyAuthenticationFailedContext"/>.
        /// </summary>
        /// <param name="context">The HttpContext the failed context applies too.</param>
        /// <param name="scheme">The scheme used when the shared key authentication handler was registered.</param>
        /// <param name="options">The <see cref=SharedKeyAuthenticationOptions"/> for the instance of
        /// <see cref="SharedKeyAuthenticationHander"/> creating this instance.</param>
        public SharedKeyAuthenticationFailedContext(
            HttpContext context,
            AuthenticationScheme scheme,
            SharedKeyAuthenticationOptions options)
            : base(context, scheme, options)
        {
        }

        public Exception Exception { get; set; }
    }
}
