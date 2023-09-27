using System;
using System.Security.Cryptography;

namespace Encryption
{
    public class PassphraseHasher
    {
        private const int DefaultIterations = 10000;
        private const int DefaultKeySize = 32;

        public byte[] HashPassphrase(string passphrase, byte[] salt)
        {
            return HashPassphrase(passphrase, salt, DefaultIterations, DefaultKeySize);
        }

        public byte[] HashPassphrase(string passphrase, byte[] salt, int iterations, int keySize)
        {
            if (string.IsNullOrWhiteSpace(passphrase))
            {
                throw new ArgumentException("Passphrase cannot be null or empty.", nameof(passphrase));
            }

            if (salt == null)
            {
                throw new ArgumentNullException(nameof(salt));
            }

            if (iterations <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(iterations), "Iterations must be greater than zero.");
            }

            if (keySize <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(keySize), "Key size must be greater than zero.");
            }

            using (Rfc2898DeriveBytes deriveBytes = new Rfc2898DeriveBytes(passphrase, salt, iterations))
            {
                return deriveBytes.GetBytes(keySize);
            }
        }
    }
}