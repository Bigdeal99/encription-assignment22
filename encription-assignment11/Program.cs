using System;
using System.IO;
using System.Security.Cryptography;
using Encription;
using Encryption;

class Program
{
    static void Main()
    {
        Console.WriteLine("Enter passphrase: ");
        string passphrase = Console.ReadLine();

        try
        {
            // Generate a random salt
            byte[] salt = GenerateSalt();

            // Derive a key using PBKDF2 with the passphrase and salt
            byte[] key = DeriveKeyFromPassphrase(passphrase, salt);

            CliMenu cliMenu = new CliMenu(key);

            while (true)
            {
                cliMenu.ShowOptions();
                cliMenu.HandleOption();
            }
        }
        catch (CryptographicException ex)
        {
            Console.WriteLine($"Error: Invalid passphrase or salt. Please check your input.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"An unexpected error occurred: {ex.Message}");
        }
        finally
        {
            // Securely clear the passphrase from memory
            ClearPassphrase(passphrase);
        }
    }

    static byte[] GenerateSalt()
    {
        try
        {
            byte[] salt = new byte[16]; // 16 bytes (128 bits) salt
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(salt);
            }
            return salt;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error generating salt: {ex.Message}");
            throw;
        }
    }

    static byte[] DeriveKeyFromPassphrase(string passphrase, byte[] salt)
    {
        try
        {
            int iterations = 10000; // Number of iterations (you can adjust this value for desired security)
            int keySize = 32; // 256 bits key size (you can adjust this value)

            using (Rfc2898DeriveBytes deriveBytes = new Rfc2898DeriveBytes(passphrase, salt, iterations))
            {
                return deriveBytes.GetBytes(keySize);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error deriving key from passphrase: {ex.Message}");
            throw;
        }
    }

    static void ClearPassphrase(string passphrase)
    {
        if (!string.IsNullOrEmpty(passphrase))
        {
            for (int i = 0; i < passphrase.Length; i++)
            {
                passphrase = passphrase.Remove(i, 1);
                passphrase = passphrase.Insert(i, " ");
            }
        }
    }
}
