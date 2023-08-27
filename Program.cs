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

    private static void EncryptFile(string inputFile, string outputFile, byte[] keyBytes)
    {
        byte[] fileBytes = File.ReadAllBytes(inputFile);
        string fileContentBase64 = Convert.ToBase64String(fileBytes);
        string encryptedContent = EncryptString(fileContentBase64, keyBytes);
        File.WriteAllText(outputFile, encryptedContent);
    }

    private static void DecryptFile(string inputFile, string outputFile, byte[] keyBytes)
    {
        string encryptedContent = File.ReadAllText(inputFile);
        string decryptedContentBase64 = DecryptString(encryptedContent, keyBytes);
        byte[] decryptedBytes = Convert.FromBase64String(decryptedContentBase64);
        File.WriteAllBytes(outputFile, decryptedBytes);
    }

    static void Main()
    {
        Console.WriteLine("Choose an operation:");
        Console.WriteLine("1. Encrypt/Decrypt Text");
        Console.WriteLine("2. Encrypt/Decrypt File");
        int operationChoice = int.Parse(Console.ReadLine());

        byte[] keyBytes;
        string key;

        switch (operationChoice)
        {
            case 1:
                Console.WriteLine("Choose an option:");
                Console.WriteLine("1. Encrypt and display text");
                Console.WriteLine("2. Decrypt text using tool");
                int choice = int.Parse(Console.ReadLine());

                if (choice == 1)
                {
                    Console.WriteLine("Do you want to:");
                    Console.WriteLine("1. Generate a key");
                    Console.WriteLine("2. Enter your own key");
                    int keyChoice = int.Parse(Console.ReadLine());

                    if (keyChoice == 1)
                    {
                        key = GenerateRandomKey(out keyBytes);
                        Console.WriteLine($"Generated Key: {key}");
                        Console.WriteLine("");
                    }
                    else
                    {
                        Console.WriteLine("Enter your key (32 bytes for AES-256 in Base64 format):");
                        key = Console.ReadLine();
                        keyBytes = Convert.FromBase64String(key);
                    }

                    string originalText = "Hello, World!";
                    string encryptedText = EncryptString(originalText, keyBytes);
                    Console.WriteLine($"Encrypted: {encryptedText}");
                    string decryptedText = DecryptString(encryptedText, keyBytes);
                    Console.WriteLine($"Decrypted: {decryptedText}");
                }
                else if (choice == 2)
                {
                    Console.WriteLine("Enter the ciphertext: ");
                    string cipherText = Console.ReadLine();
                    Console.WriteLine("Enter the encryption key (32 bytes for AES-256 in Base64 format): ");
                    key = Console.ReadLine();
                    keyBytes = Convert.FromBase64String(key);

                    try
                    {
                        string toolDecryptedText = DecryptString(cipherText, keyBytes);
                        Console.WriteLine($"Decrypted Text: {toolDecryptedText}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"An error occurred: {ex.Message}");
                    }
                }
                else
                {
                    Console.WriteLine("Invalid choice.");
                }
                break;

            case 2:
                Console.WriteLine("Choose an option:");
                Console.WriteLine("1. Encrypt a file");
                Console.WriteLine("2. Decrypt a file");
                int fileChoice = int.Parse(Console.ReadLine());

                Console.WriteLine("Enter the encryption key (32 bytes for AES-256 in Base64 format): ");
                key = Console.ReadLine();
                keyBytes = Convert.FromBase64String(key);

                switch (fileChoice)
                {
                    case 1:
                        Console.WriteLine("Enter the path of the file to encrypt:");
                        string inputFileEncrypt = Console.ReadLine();
                        Console.WriteLine("Enter the path for the encrypted output file:");
                        string outputFileEncrypt = Console.ReadLine();
                        
                        if (string.IsNullOrWhiteSpace(Path.GetFileName(outputFileEncrypt)))
                        {
                            Console.WriteLine("Please provide a valid filename for the encrypted output file.");
                            break;
                        }
                        
                        try
                        {
                            EncryptFile(inputFileEncrypt, outputFileEncrypt, keyBytes);
                            Console.WriteLine("Encryption successful!");
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"An error occurred: {ex.Message}");
                        }
                        break;

                    case 2:
                        Console.WriteLine("Enter the path of the file to decrypt:");
                        string inputFileDecrypt = Console.ReadLine();
                        Console.WriteLine("Enter the path for the decrypted output file:");
                        string outputFileDecrypt = Console.ReadLine();
                        DecryptFile(inputFileDecrypt, outputFileDecrypt, keyBytes);
                        break;

                    default:
                        Console.WriteLine("Invalid choice.");
                        break;
                }
                break;

            default:
                Console.WriteLine("Invalid operation choice.");
                break;
        }
    }
}
