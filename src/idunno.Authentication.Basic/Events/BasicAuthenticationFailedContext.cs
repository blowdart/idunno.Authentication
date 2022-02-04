// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace idunno.Authentication.Basic
{
    public class BasicAuthenticationFailedContext : ResultContext<BasicAuthenticationOptions>
    {
        public BasicAuthenticationFailedContext(
            HttpContext context,
            AuthenticationScheme scheme,
            BasicAuthenticationOptions options,
            Exception exception)
            : base(context, scheme, options)
        {
            Exception = exception;
        }

        public Exception Exception { get; set; }
    }
}
