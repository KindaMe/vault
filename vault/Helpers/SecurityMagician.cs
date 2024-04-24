using System.Text;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System.Security.Cryptography;

namespace vault.Helpers;

public class SecurityMagician
{
    public static string HashPassword(string password, string salt)
    {
        string hashed = Convert.ToBase64String(KeyDerivation.Pbkdf2(
            password: password,
            salt: Encoding.UTF8.GetBytes(salt),
            prf: KeyDerivationPrf.HMACSHA1,
            iterationCount: 10000,
            numBytesRequested: 256 / 8));

        return hashed;
    }

    public static string EncryptPassword(string password, byte[] iv, byte[] key)
    {
        using var aes = Aes.Create();
        aes.Key = key;

        using var sha256 = SHA256.Create();
        aes.IV = iv;

        var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

        using var msEncrypt = new MemoryStream();
        using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
        using (var swEncrypt = new StreamWriter(csEncrypt))
        {
            swEncrypt.Write(password);
        }

        return Convert.ToBase64String(msEncrypt.ToArray());
    }

    public static string DecryptPassword(string encryptedPassword, string iv, string key)
    {
        try
        {
            var cipherText = Convert.FromBase64String(encryptedPassword);

            using var aes = Aes.Create();
            aes.Key = Convert.FromBase64String(key);

            using var sha256 = SHA256.Create();
            aes.IV = StringToIV(iv);

            var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

            using var msDecrypt = new MemoryStream(cipherText);
            using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
            using var srDecrypt = new StreamReader(csDecrypt);

            return srDecrypt.ReadToEnd();
        }
        catch (Exception)
        {
            return "Error decrypting password";
        }
    }

    public static byte[] GenerateEncryptionKey()
    {
        using var rngCryptoServiceProvider = new RNGCryptoServiceProvider();
        var key = new byte[32]; // 256 bits
        rngCryptoServiceProvider.GetBytes(key);
        return key;
    }

    public static byte[] StringToIV(string str)
    {
        var iv = new byte[16];
        var strBytes = Encoding.UTF8.GetBytes(str);

        for (int i = 0; i < iv.Length; i++)
        {
            if (i < strBytes.Length)
            {
                iv[i] = strBytes[i];
            }
            else
            {
                iv[i] = 0; // padding with zeros
            }
        }

        return iv;
    }
}