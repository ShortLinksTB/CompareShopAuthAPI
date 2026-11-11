using System.Buffers.Binary;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Identity;

namespace CompareShopAuthAPI.Security;

public sealed class Pbkdf2Sha256PasswordHasher : IPasswordHasher<AuthUser>
{
    private const uint FormatMarker = 1;
    private const uint HmacSha256Prf = 1;
    private const int Iterations = 310_000;
    private const int SaltSize = 16;
    private const int SubkeySize = 32;
    private const int HeaderSize = 13;

    public string HashPassword(AuthUser user, string password)
    {
        ArgumentNullException.ThrowIfNull(password);
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var subkey = Rfc2898DeriveBytes.Pbkdf2(password, salt, Iterations, HashAlgorithmName.SHA256, SubkeySize);
        var payload = new byte[HeaderSize + salt.Length + subkey.Length];
        payload[0] = (byte)FormatMarker;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(1, 4), HmacSha256Prf);
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(5, 4), Iterations);
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(9, 4), SaltSize);
        salt.CopyTo(payload, HeaderSize);
        subkey.CopyTo(payload, HeaderSize + SaltSize);
        CryptographicOperations.ZeroMemory(subkey);
        return Convert.ToBase64String(payload);
    }

    public PasswordVerificationResult VerifyHashedPassword(AuthUser user, string hashedPassword, string providedPassword)
    {
        if (string.IsNullOrEmpty(hashedPassword) || providedPassword is null) return PasswordVerificationResult.Failed;
        byte[] payload;
        try { payload = Convert.FromBase64String(hashedPassword); }
        catch (FormatException) { return PasswordVerificationResult.Failed; }
        if (payload.Length < HeaderSize || payload[0] != FormatMarker) return PasswordVerificationResult.Failed;
        var prf = BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(1, 4));
        var iterations = BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(5, 4));
        var saltSize = BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(9, 4));
        if (prf != HmacSha256Prf || iterations < 1 || saltSize < 16 || HeaderSize + saltSize >= payload.Length) return PasswordVerificationResult.Failed;
        var salt = payload.AsSpan(HeaderSize, (int)saltSize);
        var expected = payload.AsSpan(HeaderSize + (int)saltSize);
        var actual = Rfc2898DeriveBytes.Pbkdf2(providedPassword, salt, (int)iterations, HashAlgorithmName.SHA256, expected.Length);
        var verified = CryptographicOperations.FixedTimeEquals(actual, expected);
        CryptographicOperations.ZeroMemory(actual);
        if (!verified) return PasswordVerificationResult.Failed;
        return iterations < Iterations ? PasswordVerificationResult.SuccessRehashNeeded : PasswordVerificationResult.Success;
    }
}
