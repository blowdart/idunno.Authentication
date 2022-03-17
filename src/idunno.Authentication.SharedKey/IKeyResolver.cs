// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

namespace idunno.Authentication.SharedKey
{
    public interface IKeyResolver
    {
        /// <summary>
        /// Returns the symmetric key for the specified <paramref name="keyId"/>.
        /// </summary>
        /// <param name="keyId">The key identifier for the key to return.</param>
        /// <returns>The symmetric key for the specified <paramref name="keyId"/>.</returns>
        byte[] GetKey(string keyId);
    }
}
