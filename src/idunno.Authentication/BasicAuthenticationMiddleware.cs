// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Text.Encodings.Web;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace idunno.Authentication
{
    /// <summary>
    /// Basic authentication middleware component which is added to an HTTP pipeline. This class is not
    /// created by application code directly, instead it is added by calling the the IAppBuilder 
    /// UseBasicAuthentication extension method.
    /// </summary>
    public class BasicAuthenticationMiddleware : AuthenticationMiddleware<BasicAuthenticationOptions>
    {
        /// <summary>
        /// Creates an instance of <see cref="BasicAuthenticationMiddleware"/>.
        /// </summary>
        /// <remarks>
        /// This class is not created by application code directly, instead it is added by 
        /// calling the the IAppBuilder UseBasicAuthentication extension method.
        /// </remarks>
        /// <param name="next">The next middleware in the pipeline.</param>
        /// <param name="loggerFactory">The logger factory to use.</param>
        /// <param name="encoder">The URL encoder to use.</param>
        /// <param name="options">Configuration options for the middleware.</param>
        public BasicAuthenticationMiddleware(
            RequestDelegate next,
            ILoggerFactory loggerFactory,
            UrlEncoder encoder,
            BasicAuthenticationOptions options)
            : base(next, options, loggerFactory, encoder)
        {
            if (Options.Events == null)
            {
                Options.Events = new BasicAuthenticationEvents();
            }
        }

        /// <summary>
        /// Called by the AuthenticationMiddleware base class to create a per-request handler. 
        /// </summary>
        /// <returns>A new instance of the request handler</returns>
        protected override AuthenticationHandler<BasicAuthenticationOptions> CreateHandler()
        {
            return new BasicAuthenticationHandler();
        }
    }
}
