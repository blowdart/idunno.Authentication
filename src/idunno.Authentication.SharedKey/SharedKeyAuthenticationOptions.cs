// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Microsoft.AspNetCore.Authentication;
using System;

namespace idunno.Authentication.SharedKey
{
    public class SharedKeyAuthenticationOptions : AuthenticationSchemeOptions
    {
        /// <summary>
        /// The object provided by the application to process events raised by the shared key authentication middleware.
        /// The application may implement the interface fully, or it may create an instance of SharedKeyAuthenticationEvents
        /// and assign delegates only to the events it wants to process.
        /// </summary>
        public new SharedKeyAuthenticationEvents Events
        {
            get { return (SharedKeyAuthenticationEvents)base.Events; }

            set { base.Events = value; }
        }

        public Func<string, byte[]> KeyResolver { get; set; } = (keyId) => Array.Empty<byte>();

        public TimeSpan MaximumMessageValidity { get; set; } = new TimeSpan(0, 15, 0);
    }
}
