﻿// Copyright (c) Barry Dorrans. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace idunno.Authentication.Certificate
{
    public static class X509Certificate2Extensions
    {
        public static bool IsSelfSigned(this X509Certificate2 certificate)
        {
            if (certificate == null)
            {
                throw new ArgumentNullException(nameof(certificate));
            }

            return certificate.SubjectName.RawData.SequenceEqual(certificate.IssuerName.RawData);
        }

        public static string SHA256Thumprint(this X509Certificate2 certificate)
        {
            if (certificate == null)
            {
                throw new ArgumentNullException(nameof(certificate));
            }

            using (var hasher = SHA256.Create())
            {
                var certificateHash = hasher.ComputeHash(certificate.RawData);
                string hashAsString = string.Empty;
                foreach (byte hashByte in certificateHash)
                {
                    hashAsString += hashByte.ToString("x2", CultureInfo.InvariantCulture);
                }

                return hashAsString;
            }
        }
    }
}
