using Microsoft.AspNetCore.Mvc.ModelBinding.Binders;
using System.Collections.ObjectModel;
using System.Security.Cryptography;

namespace idunno.Authentication.SharedKey.Sample
{
    internal class KeyResolver
    {
        private static readonly Dictionary<string, byte[]> knownKeyIdentifiersAndKey = new();

        public static byte[] GetKey(string keyId)
        {
            if (!knownKeyIdentifiersAndKey.ContainsKey(keyId))
            {
                return Array.Empty<byte>();
            }
            else
            {
                return knownKeyIdentifiersAndKey[keyId];
            }
        }

        public static void Add(string keyId, byte[] key)
        {
            knownKeyIdentifiersAndKey[keyId] = key;
        }

        public static void Add(string keyId)
        {
            byte[] newKey = new byte[64];
            using var randomNumberGenerator = RandomNumberGenerator.Create();
            randomNumberGenerator.GetBytes(newKey);

            knownKeyIdentifiersAndKey[keyId] = newKey;
        }

        public static IReadOnlyDictionary<string, byte[]> Keys => new ReadOnlyDictionary<string, byte[]>(knownKeyIdentifiersAndKey);
    }
}
