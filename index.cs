using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

class Program
{
    private static string EncryptString(string plainText, byte[] keyBytes)
    {
        using (Aes aes = Aes.Create())
        {
            aes.Key = keyBytes;
            aes.IV = new byte[16]; // Initialization vector with 16 zeros

            ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter streamWriter = new StreamWriter(cryptoStream))
                    {
                        streamWriter.Write(plainText);
                    }
                    return Convert.ToBase64String(memoryStream.ToArray());
                }
            }
        }
    }

    private static string DecryptString(string cipherText, byte[] keyBytes)
    {
        using (Aes aes = Aes.Create())
        {
            aes.Key = keyBytes;
            aes.IV = new byte[16]; // Initialization vector with 16 zeros

            ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

            using (MemoryStream memoryStream = new MemoryStream(Convert.FromBase64String(cipherText)))
            {
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader streamReader = new StreamReader(cryptoStream))
                    {
                        return streamReader.ReadToEnd();
                    }
                }
            }
        }
    }

    private static string GenerateRandomKey(out byte[] keyBytes)
    {
        using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
        {
            keyBytes = new byte[32];
            rng.GetBytes(keyBytes);
            return Convert.ToBase64String(keyBytes);
        }
    }

    static void Main()
    {
        Console.WriteLine("Choose an option:");
        Console.WriteLine("1. Encrypt and display text");
        Console.WriteLine("2. Decrypt text using tool");
        int choice = int.Parse(Console.ReadLine());

        switch (choice)
        {
            case 1:
                Console.WriteLine("Do you want to:");
                Console.WriteLine("1. Generate a key");
                Console.WriteLine("2. Enter your own key");
                int keyChoice = int.Parse(Console.ReadLine());
                byte[] keyBytes;

                if (keyChoice == 1)
                {
                    string key = GenerateRandomKey(out keyBytes);
                    Console.WriteLine($"Generated Key: {key}");
                    Console.WriteLine("");
                }
                else
                {
                    Console.WriteLine("Enter your key (32 bytes for AES-256 in Base64 format):");
                    string key = Console.ReadLine();
                    keyBytes = Convert.FromBase64String(key);
                }

                string originalText = "Hello, World!";
                string encryptedText = EncryptString(originalText, keyBytes);
                Console.WriteLine($"Encrypted: {encryptedText}");
                string decryptedText = DecryptString(encryptedText, keyBytes);
                Console.WriteLine($"Decrypted: {decryptedText}");
                break;

            case 2:
                Console.WriteLine("Enter the ciphertext: ");
                string cipherText = Console.ReadLine();
                Console.WriteLine("Enter the encryption key (32 bytes for AES-256 in Base64 format): ");
                string decryptionKey = Console.ReadLine();
                byte[] decryptionKeyBytes = Convert.FromBase64String(decryptionKey);
                try
                {
                    string toolDecryptedText = DecryptString(cipherText, decryptionKeyBytes);
                    Console.WriteLine($"Decrypted Text: {toolDecryptedText}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"An error occurred: {ex.Message}");
                }
                break;

            default:
                Console.WriteLine("Invalid choice.");
                break;
        }
    }
}
