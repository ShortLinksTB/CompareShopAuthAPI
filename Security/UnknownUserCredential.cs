using System.Security.Cryptography;
using Microsoft.AspNetCore.Identity;

namespace CompareShopAuthAPI.Security;

public sealed class UnknownUserCredential
{
    private readonly AuthUser _user = new() { Id = "unknown-user-timing-equalizer" };
    private readonly string _hash;
    private readonly Pbkdf2Sha256PasswordHasher _hasher = new();

    public UnknownUserCredential()
    {
        var ephemeralPassword = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        _hash = _hasher.HashPassword(_user, ephemeralPassword);
    }

    public void Verify(string candidate) => _ = _hasher.VerifyHashedPassword(_user, _hash, candidate);
}
