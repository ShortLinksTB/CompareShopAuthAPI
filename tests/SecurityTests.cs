using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using CompareShopAuthAPI;
using CompareShopAuthAPI.Application;
using CompareShopAuthAPI.Security;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Logging.Abstractions;
using System.Net;
using Xunit;

namespace CompareShopAuthAPI.Tests;

public sealed class SecurityTests
{
    [Fact]
    public void EncryptedOutboxPayloadRoundTrips()
    {
        var key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        var protector = new SecretPayloadProtector(Configuration(new Dictionary<string, string?> { ["Outbox:EncryptionKey"] = key }));
        var original = new EmailSendRequested("EmailSendRequested", Guid.NewGuid(), 1, "person@example.com", "auth-verify", "en", "auth-verify", new Dictionary<string, string> { ["token"] = "synthetic-token" });
        var sealedPayload = protector.Protect(original);
        var opened = protector.Unprotect<EmailSendRequested>(sealedPayload.Nonce, sealedPayload.Ciphertext, sealedPayload.Tag);
        Assert.Equal(original.RequestId, opened.RequestId);
        Assert.Equal(original.TemplateData["token"], opened.TemplateData["token"]);
        Assert.NotEqual(original.TemplateData["token"], System.Text.Encoding.UTF8.GetString(sealedPayload.Ciphertext));
    }

    [Fact]
    public void EncryptedOutboxRejectsTamperedCiphertext()
    {
        var protector = new SecretPayloadProtector(Configuration(new Dictionary<string, string?> { ["Outbox:EncryptionKey"] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)) }));
        var payload = protector.Protect(new { Secret = "opaque" });
        payload.Ciphertext[0] ^= 0x20;
        Assert.ThrowsAny<CryptographicException>(() => protector.Unprotect<Dictionary<string, string>>(payload.Nonce, payload.Ciphertext, payload.Tag));
    }

    [Fact]
    public void AccessTokenUsesConfiguredIssuerAudienceAndKid()
    {
        using var rsa = RSA.Create(2048);
        var config = Configuration(new Dictionary<string, string?>
        {
            ["Jwt:PrivateKeyPem"] = rsa.ExportPkcs8PrivateKeyPem(),
            ["Jwt:Issuer"] = "https://auth.test",
            ["Jwt:Audience"] = "compareshop-api",
            ["Jwt:KeyId"] = "key-1"
        });
        using var issuer = new AccessTokenIssuer(config);
        var user = new AuthIdentityUser("subject-1", "person@example.com", true);
        var issuedAt = DateTimeOffset.Parse("2026-11-11T14:00:00Z");
        var handler = new JwtSecurityTokenHandler();
        var token = handler.ReadJwtToken(issuer.Issue(user, issuedAt));
        Assert.Equal("https://auth.test", token.Issuer);
        Assert.Contains("compareshop-api", token.Audiences);
        Assert.Equal("key-1", token.Header.Kid);
        Assert.Equal("subject-1", token.Claims.Single(c => c.Type == JwtRegisteredClaimNames.Sub).Value);
        Assert.Equal(15 * 60, (token.ValidTo - issuedAt.UtcDateTime).TotalSeconds);
        Assert.Contains("key-1", System.Text.Json.JsonSerializer.Serialize(issuer.Jwks()));
    }

    [Fact]
    public void PasswordHasherUsesPbkdf2HmacSha256AtRequiredIterationFloor()
    {
        var hasher = new Pbkdf2Sha256PasswordHasher();
        var user = new AuthUser { Id = "user-1" };
        var encoded = hasher.HashPassword(user, "Correct-Horse-Battery-9!");
        var payload = Convert.FromBase64String(encoded);
        Assert.Equal(1, payload[0]);
        Assert.Equal(1U, System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(1, 4)));
        Assert.Equal(310_000U, System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(5, 4)));
        Assert.Equal(Microsoft.AspNetCore.Identity.PasswordVerificationResult.Success, hasher.VerifyHashedPassword(user, encoded, "Correct-Horse-Battery-9!"));
        Assert.Equal(Microsoft.AspNetCore.Identity.PasswordVerificationResult.Failed, hasher.VerifyHashedPassword(user, encoded, "Wrong-Passphrase"));
    }

    [Fact]
    public void JwksRotationRetainsPreviousPublicKeyForExistingTokens()
    {
        using var oldKey = RSA.Create(2048);
        using var currentKey = RSA.Create(2048);
        var oldConfiguration = Configuration(new Dictionary<string, string?>
        {
            ["Jwt:PrivateKeyPem"] = oldKey.ExportPkcs8PrivateKeyPem(), ["Jwt:KeyId"] = "old-key",
            ["Jwt:Issuer"] = "https://auth.test", ["Jwt:Audience"] = "compareshop-api"
        });
        using var oldIssuer = new AccessTokenIssuer(oldConfiguration);
        var oldToken = oldIssuer.Issue(new AuthIdentityUser("subject", "person@example.test", true), DateTimeOffset.UtcNow);
        var newConfiguration = Configuration(new Dictionary<string, string?>
        {
            ["Jwt:PrivateKeyPem"] = currentKey.ExportPkcs8PrivateKeyPem(), ["Jwt:KeyId"] = "current-key",
            ["Jwt:PreviousPublicKeyPem"] = oldKey.ExportSubjectPublicKeyInfoPem(), ["Jwt:PreviousKeyId"] = "old-key",
            ["Jwt:Issuer"] = "https://auth.test", ["Jwt:Audience"] = "compareshop-api"
        });
        using var rotatedIssuer = new AccessTokenIssuer(newConfiguration);
        var validator = new JwtSecurityTokenHandler { MapInboundClaims = false };
        var principal = validator.ValidateToken(oldToken, rotatedIssuer.ValidationParameters(), out _);
        Assert.Equal("subject", principal.FindFirst("sub")?.Value);
        Assert.Contains("old-key", System.Text.Json.JsonSerializer.Serialize(rotatedIssuer.Jwks()));
    }

    [Fact]
    public async Task DisabledTurnstileDoesNotCallSiteverifyOrRequireToken()
    {
        var client = new TurnstileVerifier(new StubClientFactory(_ => throw new InvalidOperationException("unexpected request")), Configuration(new Dictionary<string, string?>()), Environment("Development"), NullLogger<TurnstileVerifier>.Instance);
        Assert.True((await client.VerifyAsync(null, null, CancellationToken.None)).Accepted);
    }

    [Fact]
    public async Task EnabledTurnstileRequiresValidSuccessAndAllowedHostname()
    {
        var config = Configuration(new Dictionary<string, string?>
        {
            ["Turnstile:Enabled"] = "true", ["Turnstile:Secret"] = "secret-for-test-only",
            ["Turnstile:AllowedHostnames:0"] = "example.com"
        });
        var response = new StubClientFactory(_ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{\"success\":true,\"hostname\":\"example.com\"}") });
        var verifier = new TurnstileVerifier(response, config, Environment("Development"), NullLogger<TurnstileVerifier>.Instance);
        Assert.True((await verifier.VerifyAsync("test-token", "127.0.0.1", CancellationToken.None)).Accepted);
        var mismatch = new TurnstileVerifier(new StubClientFactory(_ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{\"success\":true,\"hostname\":\"attacker.example\"}") }), config, Environment("Development"), NullLogger<TurnstileVerifier>.Instance);
        Assert.False((await mismatch.VerifyAsync("test-token", null, CancellationToken.None)).Accepted);
        var productionTestHost = new TurnstileVerifier(new StubClientFactory(_ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{\"success\":true,\"hostname\":\"example.com\"}") }), config, Environment("Production"), NullLogger<TurnstileVerifier>.Instance);
        Assert.False((await productionTestHost.VerifyAsync("test-token", null, CancellationToken.None)).Accepted);
    }

    [Fact]
    public async Task MissingOrRejectedTurnstileTokenCannotUseTransportBypass()
    {
        var config = Configuration(new Dictionary<string, string?> { ["Turnstile:Enabled"] = "true", ["Turnstile:Secret"] = "secret", ["Turnstile:AllowUnavailableInDev"] = "true" });
        var verifier = new TurnstileVerifier(new StubClientFactory(_ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{\"success\":false,\"hostname\":\"example.com\"}") }), config, Environment("Development"), NullLogger<TurnstileVerifier>.Instance);
        Assert.False((await verifier.VerifyAsync(null, null, CancellationToken.None)).Accepted);
        Assert.False((await verifier.VerifyAsync("always-fail", null, CancellationToken.None)).Accepted);
    }

    [Fact]
    public async Task TurnstileTransportBypassIsDevelopmentOnly()
    {
        var config = Configuration(new Dictionary<string, string?> { ["Turnstile:Enabled"] = "true", ["Turnstile:Secret"] = "secret", ["Turnstile:AllowUnavailableInDev"] = "true", ["Turnstile:AllowedHostnames:0"] = "example.com" });
        var failing = new StubClientFactory(_ => throw new HttpRequestException("network down"));
        Assert.True((await new TurnstileVerifier(failing, config, Environment("Development"), NullLogger<TurnstileVerifier>.Instance).VerifyAsync("token", null, CancellationToken.None)).Accepted);
        Assert.False((await new TurnstileVerifier(failing, config, Environment("Production"), NullLogger<TurnstileVerifier>.Instance).VerifyAsync("token", null, CancellationToken.None)).Accepted);
    }

    private static IConfiguration Configuration(Dictionary<string, string?> values) => new ConfigurationBuilder().AddInMemoryCollection(values).Build();

    private static IWebHostEnvironment Environment(string name) => new TestEnvironment { EnvironmentName = name };

    private sealed class StubClientFactory(Func<HttpRequestMessage, HttpResponseMessage> respond) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(new StubHandler(respond), disposeHandler: true);
    }

    private sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => Task.FromResult(respond(request));
    }

    private sealed class TestEnvironment : IWebHostEnvironment
    {
        public string ApplicationName { get; set; } = "Tests";
        public IFileProvider WebRootFileProvider { get; set; } = new NullFileProvider();
        public string WebRootPath { get; set; } = "";
        public string EnvironmentName { get; set; } = "Development";
        public string ContentRootPath { get; set; } = "";
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
