using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Encryption
{
    public class EncryptionHelper : IDisposable
    {
        private const int DefaultKeySize = 256;

        private readonly byte[] _key;
        private readonly Aes _aes;

        public EncryptionHelper(byte[] key)
        {
            if (key == null || key.Length != DefaultKeySize / 8)
            {
                throw new ArgumentException("Invalid key size. Key must be 256 bits.");
            }

            _key = key;
            _aes = Aes.Create();
            _aes.KeySize = DefaultKeySize;
            _aes.Key = _key;
        }

        public byte[] EncryptMessage(string message)
        {
            _aes.GenerateIV(); // Generate a random IV for each encryption

            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (ICryptoTransform encryptor = _aes.CreateEncryptor())
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    byte[] messageBytes = Encoding.UTF8.GetBytes(message);
                    csEncrypt.Write(messageBytes, 0, messageBytes.Length);
                }

                byte[] iv = _aes.IV;
                byte[] encryptedData = msEncrypt.ToArray();
                byte[] result = new byte[iv.Length + encryptedData.Length];

                Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
                Buffer.BlockCopy(encryptedData, 0, result, iv.Length, encryptedData.Length);

                return result;
            }
        }

        public string DecryptMessage(byte[] encryptedMessage)
        {
            if (encryptedMessage == null || encryptedMessage.Length == 0)
            {
                throw new ArgumentException("Invalid encrypted message.");
            }

            int ivSize = _aes.BlockSize / 8;
            if (encryptedMessage.Length < ivSize)
            {
                throw new ArgumentException("Invalid IV in the encrypted message.");
            }

            _aes.IV = encryptedMessage.Take(ivSize).ToArray();

            using (MemoryStream msDecrypt = new MemoryStream(encryptedMessage, ivSize, encryptedMessage.Length - ivSize))
            {
                using (ICryptoTransform decryptor = _aes.CreateDecryptor())
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                {
                    return srDecrypt.ReadToEnd();
                }
            }
        }

        public void Dispose()
        {
            _aes.Dispose();
        }
    }
}
