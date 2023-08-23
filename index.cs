using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;


class DecryptionTool
{
    public static void Main()
    {
        Console.WriteLine("Welcome to the Decryption Tool!");

        // Get ciphertext from the user
        Console.Write("Enter the ciphertext: ");
        string cipherText = Console.ReadLine();

        // Get the encryption key from the user
        Console.Write("Enter the encryption key (32 bytes for AES-256): ");
        string key = Console.ReadLine();

        try
        {
            // Decrypt the ciphertext
            string decryptedText = DecryptString(cipherText, key);

            // Display the decrypted text
            Console.WriteLine($"Decrypted Text: {decryptedText}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"An error occurred: {ex.Message}");
        }
    }
}
class Program
{
    private static string EncryptString(string plainText, string key)
    {
        using (Aes aes = Aes.Create())
        {
            aes.Key = Encoding.UTF8.GetBytes(key);
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

    private static string DecryptString(string cipherText, string key)
    {
        using (Aes aes = Aes.Create())
        {
            aes.Key = Encoding.UTF8.GetBytes(key);
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

    static void Main()
    {
        string key = "12345678901234567890123456789012"; // 32 bytes for AES-256
        string originalText = "Hello, World!";

        string encryptedText = EncryptString(originalText, key);
        Console.WriteLine($"Encrypted: {encryptedText}");

        string decryptedText = DecryptString(encryptedText, key);
        Console.WriteLine($"Decrypted: {decryptedText}");
    }
}
