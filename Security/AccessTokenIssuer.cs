using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace CompareShopAuthAPI.Security;

public sealed class AccessTokenIssuer : IDisposable
{
    private readonly RSA? _rsa;
    private readonly RSA? _previousRsa;
    private readonly SigningCredentials? _credentials;
    private readonly string _kid;
    private readonly string _previousKid;
    private readonly string _issuer;
    private readonly string _audience;

    public AccessTokenIssuer(IConfiguration configuration)
    {
        _issuer = configuration["Jwt:Issuer"] ?? "https://auth-compareshop-dev.giamha.online";
        _audience = configuration["Jwt:Audience"] ?? "compareshop-api";
        _kid = configuration["Jwt:KeyId"] ?? "current";
        _previousKid = configuration["Jwt:PreviousKeyId"] ?? "previous";
        var pem = configuration["Jwt:PrivateKeyPem"];
        var path = configuration["Jwt:PrivateKeyPath"];
        if (string.IsNullOrWhiteSpace(pem) && !string.IsNullOrWhiteSpace(path) && File.Exists(path)) pem = File.ReadAllText(path);
        if (!string.IsNullOrWhiteSpace(pem))
        {
            _rsa = RSA.Create();
            _rsa.ImportFromPem(pem);
            if (_rsa.KeySize < 2048) throw new InvalidOperationException("RS256 signing key must be at least 2048 bits.");
            try
            {
                if (_rsa.ExportParameters(true).D is null) throw new InvalidOperationException("Configured JWT key does not contain private signing material.");
            }
            catch (CryptographicException ex) { throw new InvalidOperationException("Configured JWT key does not contain private signing material.", ex); }
            _credentials = new SigningCredentials(new RsaSecurityKey(_rsa) { KeyId = _kid }, SecurityAlgorithms.RsaSha256);
        }
        var previousPem = configuration["Jwt:PreviousPublicKeyPem"];
        if (!string.IsNullOrWhiteSpace(previousPem))
        {
            _previousRsa = RSA.Create();
            _previousRsa.ImportFromPem(previousPem);
            if (_previousRsa.KeySize < 2048) throw new InvalidOperationException("Previous RS256 public key must be at least 2048 bits.");
            if (string.Equals(_previousKid, _kid, StringComparison.Ordinal)) throw new InvalidOperationException("Current and previous JWT key identifiers must differ.");
        }
    }

    public bool IsConfigured => _credentials is not null;

    public string Issue(AuthUser user, DateTimeOffset now)
    {
        if (_credentials is null) throw new InvalidOperationException("JWT signing key is not configured.");
        var token = new JwtSecurityToken(_issuer, _audience,
            [new Claim(JwtRegisteredClaimNames.Sub, user.Id), new Claim(JwtRegisteredClaimNames.Email, user.Email ?? ""), new Claim("email_verified", "true", ClaimValueTypes.Boolean)],
            now.UtcDateTime, now.AddMinutes(15).UtcDateTime, _credentials);
        token.Header["kid"] = _kid;
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public object Jwks()
    {
        if (_rsa is null && _previousRsa is null) return new { keys = Array.Empty<object>() };
        var keys = new List<object>();
        if (_rsa is not null) keys.Add(ExportJwk(_rsa, _kid));
        if (_previousRsa is not null) keys.Add(ExportJwk(_previousRsa, _previousKid));
        return new { keys };
    }

    public TokenValidationParameters ValidationParameters() => new()
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKeyResolver = (_, _, kid, _) => new[] { (_rsa, _kid), (_previousRsa, _previousKid) }
            .Where(pair => pair.Item1 is not null && pair.Item2 == kid)
            .Select(pair => new RsaSecurityKey(pair.Item1!) { KeyId = pair.Item2 }),
        ValidIssuer = _issuer,
        ValidateIssuer = true,
        ValidAudience = _audience,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidAlgorithms = [SecurityAlgorithms.RsaSha256],
        ClockSkew = TimeSpan.FromSeconds(30)
    };

    private static object ExportJwk(RSA rsa, string keyId)
    {
        var p = rsa.ExportParameters(false);
        return new { kty = "RSA", use = "sig", alg = "RS256", kid = keyId, n = Base64UrlEncoder.Encode(p.Modulus), e = Base64UrlEncoder.Encode(p.Exponent) };
    }

    public void Dispose() { _rsa?.Dispose(); _previousRsa?.Dispose(); }
}
