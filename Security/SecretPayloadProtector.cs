using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace CompareShopAuthAPI.Security;

public sealed class SecretPayloadProtector(IConfiguration configuration)
{
    private readonly byte[] _key = ReadKey(configuration["Outbox:EncryptionKey"]);

    public (byte[] Nonce, byte[] Ciphertext, byte[] Tag) Protect<T>(T value)
    {
        var nonce = RandomNumberGenerator.GetBytes(12);
        var plaintext = JsonSerializer.SerializeToUtf8Bytes(value);
        var cipher = new byte[plaintext.Length];
        var tag = new byte[16];
        using var aes = new AesGcm(_key, 16);
        aes.Encrypt(nonce, plaintext, cipher, tag);
        CryptographicOperations.ZeroMemory(plaintext);
        return (nonce, cipher, tag);
    }

    public T Unprotect<T>(byte[] nonce, byte[] ciphertext, byte[] tag)
    {
        var plaintext = new byte[ciphertext.Length];
        using var aes = new AesGcm(_key, 16);
        aes.Decrypt(nonce, ciphertext, tag, plaintext);
        try { return JsonSerializer.Deserialize<T>(plaintext) ?? throw new CryptographicException("Invalid encrypted payload."); }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
    }

    private static byte[] ReadKey(string? configured)
    {
        if (string.IsNullOrWhiteSpace(configured)) throw new InvalidOperationException("Outbox encryption key is not configured.");
        var key = Convert.FromBase64String(configured);
        if (key.Length != 32) throw new InvalidOperationException("Outbox encryption key must be 256 bits.");
        return key;
    }
}

public sealed record EmailSendRequested(
    [property: JsonPropertyName("messageType")]
    string MessageType,
    [property: JsonPropertyName("requestId")]
    Guid RequestId,
    [property: JsonPropertyName("version")]
    int Version,
    [property: JsonPropertyName("to")]
    string To,
    [property: JsonPropertyName("templateKey")]
    string TemplateKey,
    [property: JsonPropertyName("locale")]
    string Locale,
    [property: JsonPropertyName("subjectKey")]
    string SubjectKey,
    [property: JsonPropertyName("templateData")]
    Dictionary<string, string> TemplateData);
