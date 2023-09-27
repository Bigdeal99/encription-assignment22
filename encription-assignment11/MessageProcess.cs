using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Encryption
{
    public class MessageProcess
    {
        private const int KeySize = 256;
        private const string EncryptedMessageFileName = "encryptedMessage.bin";

        private readonly byte[] _key;

        public MessageProcess(byte[] key)
        {
            if (key == null || key.Length != KeySize / 8)
            {
                throw new ArgumentException("Invalid key size. Key must be 256 bits.");
            }

            this._key = key;
        }

        public void EncryptAndSaveMessage(string message)
        {
            // Encrypt the message and save it as a file
            byte[] encryptedMessage = EncryptMessage(Encoding.UTF8.GetBytes(message));
            File.WriteAllBytes(EncryptedMessageFileName, encryptedMessage);
        }

        public string ReadAndDecryptMessage()
        {
            if (!File.Exists(EncryptedMessageFileName))
            {
                Console.WriteLine("No encrypted message found.");
                return null;
            }

            // Read the encrypted message from the file
            byte[] encryptedMessage = File.ReadAllBytes(EncryptedMessageFileName);

            // Decrypt and return as a string
            return Encoding.UTF8.GetString(DecryptMessage(encryptedMessage));
        }

        private byte[] EncryptMessage(byte[] message)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.KeySize = KeySize;
                aesAlg.Key = _key;

                // Initialize other AES parameters (e.g., IV)
                aesAlg.GenerateIV();

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (ICryptoTransform encryptor = aesAlg.CreateEncryptor())
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        csEncrypt.Write(message, 0, message.Length);
                        csEncrypt.FlushFinalBlock();
                    }

                    byte[] iv = aesAlg.IV;
                    byte[] encryptedData = msEncrypt.ToArray();
                    byte[] result = new byte[iv.Length + encryptedData.Length];

                    Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
                    Buffer.BlockCopy(encryptedData, 0, result, iv.Length, encryptedData.Length);

                    return result;
                }
            }
        }

        private byte[] DecryptMessage(byte[] encryptedMessage)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.KeySize = KeySize;
                aesAlg.Key = _key;

               
                byte[] iv = new byte[aesAlg.BlockSize / 8];
                Buffer.BlockCopy(encryptedMessage, 0, iv, 0, iv.Length);
                aesAlg.IV = iv;

                using (MemoryStream msDecrypt = new MemoryStream(encryptedMessage, iv.Length, encryptedMessage.Length - iv.Length))
                using (ICryptoTransform decryptor = aesAlg.CreateDecryptor())
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                using (MemoryStream msPlaintext = new MemoryStream())
                {
                    csDecrypt.CopyTo(msPlaintext);
                    return msPlaintext.ToArray();
                }
            }
        }
    }
}
