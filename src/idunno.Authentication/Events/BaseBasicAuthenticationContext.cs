// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace idunno.Authentication
{
    public class BaseBasicAuthenticationContext : BaseControlContext
    {
        public BaseBasicAuthenticationContext(HttpContext context, BasicAuthenticationOptions options) : base(context)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            Options = options;
        }

        public BasicAuthenticationOptions Options { get; }
    }
}
