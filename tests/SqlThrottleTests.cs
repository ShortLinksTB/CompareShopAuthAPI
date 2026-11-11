using System.Security.Cryptography;
using CompareShopAuthAPI.Data;
using Microsoft.EntityFrameworkCore;
using Testcontainers.MsSql;
using Xunit;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using CompareShopAuthAPI.Security;

namespace CompareShopAuthAPI.Tests;

public sealed class SqlThrottleTests : IAsyncLifetime
{
    private readonly MsSqlContainer _sql = new MsSqlBuilder()
        .WithPassword("Aa1!" + Convert.ToHexString(RandomNumberGenerator.GetBytes(16)))
        .Build();

    public Task InitializeAsync() => _sql.StartAsync();
    public Task DisposeAsync() => _sql.DisposeAsync().AsTask();

    [Fact]
    public async Task SqlThrottleEnforcesLimitAcrossDbContexts()
    {
        var options = new DbContextOptionsBuilder<AuthDbContext>().UseSqlServer(_sql.GetConnectionString()).Options;
        await using (var db = new AuthDbContext(options))
        {
            await db.Database.MigrateAsync();
            var throttle = CreateThrottle(db);
            Assert.True(await throttle.TryConsumeAsync("forgot:email", "person@example.com", 2, TimeSpan.FromHours(1), CancellationToken.None));
            Assert.True(await throttle.TryConsumeAsync("forgot:email", "person@example.com", 2, TimeSpan.FromHours(1), CancellationToken.None));
            Assert.False(await throttle.TryConsumeAsync("forgot:email", "person@example.com", 2, TimeSpan.FromHours(1), CancellationToken.None));
        }
        await using var nextRequest = new AuthDbContext(options);
        Assert.False(await CreateThrottle(nextRequest).TryConsumeAsync("forgot:email", "person@example.com", 2, TimeSpan.FromHours(1), CancellationToken.None));
    }

    [Fact]
    public async Task AuthApiSupportsVerificationLoginRefreshAndPinReset()
    {
        var options = new DbContextOptionsBuilder<AuthDbContext>().UseSqlServer(_sql.GetConnectionString()).Options;
        await using (var db = new AuthDbContext(options)) await db.Database.MigrateAsync();
        using var rsa = RSA.Create(2048);
        using var app = new AuthApiFactory(_sql.GetConnectionString(), rsa.ExportPkcs8PrivateKeyPem());
        using var client = app.CreateClient();
        var email = $"test-{Guid.NewGuid():N}@example.test";
        const string initialPassword = "First-Blue-Passphrase-994!";
        var unknownForgot = await client.PostAsJsonAsync("/api/v1/auth/forgot-password", new { email = $"missing-{Guid.NewGuid():N}@example.test" });
        var unknownLogin = await client.PostAsJsonAsync("/api/v1/auth/login", new { email = $"missing-{Guid.NewGuid():N}@example.test", password = initialPassword });
        Assert.Equal(System.Net.HttpStatusCode.Unauthorized, unknownLogin.StatusCode);
        var registered = await client.PostAsJsonAsync("/api/v1/auth/register", new { email, password = initialPassword });
        Assert.Equal(System.Net.HttpStatusCode.Accepted, registered.StatusCode);
        var duplicateRegistration = await client.PostAsJsonAsync("/api/v1/auth/register", new { email, password = initialPassword });
        Assert.Equal(System.Net.HttpStatusCode.Accepted, duplicateRegistration.StatusCode);
        Assert.Equal(await registered.Content.ReadAsStringAsync(), await duplicateRegistration.Content.ReadAsStringAsync());
        Assert.Equal(System.Net.HttpStatusCode.Unauthorized, (await client.PostAsJsonAsync("/api/v1/auth/login", new { email, password = initialPassword })).StatusCode);

        EmailSendRequested verifyMessage;
        await using (var db = new AuthDbContext(options))
        {
            var protector = app.Services.GetRequiredService<SecretPayloadProtector>();
            var rows = await db.EmailOutbox.OrderByDescending(x => x.CreatedAt).ToListAsync();
            verifyMessage = rows.Select(x => protector.Unprotect<EmailSendRequested>(x.Nonce, x.Ciphertext, x.Tag)).First(x => x.TemplateKey == "auth-verify");
        }
        var verifyLink = verifyMessage.TemplateData["verificationLink"];
        var oldVerificationToken = Uri.UnescapeDataString(System.Text.RegularExpressions.Regex.Match(verifyLink, "[?&]token=([^&]+)").Groups[1].Value);
        Assert.Equal(System.Net.HttpStatusCode.Accepted, (await client.PostAsJsonAsync("/api/v1/auth/resend-verification", new { email })).StatusCode);
        await using (var db = new AuthDbContext(options))
        {
            var rows = await db.EmailOutbox.OrderByDescending(x => x.CreatedAt).ToListAsync();
            var protector = app.Services.GetRequiredService<SecretPayloadProtector>();
            verifyMessage = rows.Select(x => protector.Unprotect<EmailSendRequested>(x.Nonce, x.Ciphertext, x.Tag)).First(x => x.TemplateKey == "auth-verify");
        }
        var verificationLink = verifyMessage.TemplateData["verificationLink"];
        var verificationToken = Uri.UnescapeDataString(System.Text.RegularExpressions.Regex.Match(verificationLink, "[?&]token=([^&]+)").Groups[1].Value);
        Assert.Equal(System.Net.HttpStatusCode.BadRequest, (await client.PostAsJsonAsync("/api/v1/auth/verify-email", new { email, token = oldVerificationToken })).StatusCode);
        var verified = await client.PostAsJsonAsync("/api/v1/auth/verify-email", new { email, token = verificationToken });
        Assert.Equal(System.Net.HttpStatusCode.OK, verified.StatusCode);

        var login = await client.PostAsJsonAsync("/api/v1/auth/login", new { email, password = initialPassword });
        Assert.Equal(System.Net.HttpStatusCode.OK, login.StatusCode);
        var accessToken = (await login.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("accessToken").GetString()!;
        var originalCookie = Cookie(login);
        using (var meRequest = new HttpRequestMessage(HttpMethod.Get, "/api/v1/auth/me"))
        {
            meRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            Assert.Equal(System.Net.HttpStatusCode.OK, (await client.SendAsync(meRequest)).StatusCode);
        }
        using var refreshRequest = Mutation("/api/v1/auth/refresh", originalCookie);
        var refresh = await client.SendAsync(refreshRequest);
        Assert.Equal(System.Net.HttpStatusCode.OK, refresh.StatusCode);
        var rotatedCookie = Cookie(refresh);
        using var reuseRequest = Mutation("/api/v1/auth/refresh", originalCookie);
        Assert.Equal(System.Net.HttpStatusCode.Unauthorized, (await client.SendAsync(reuseRequest)).StatusCode);
        using var revokedRequest = Mutation("/api/v1/auth/refresh", rotatedCookie);
        Assert.Equal(System.Net.HttpStatusCode.Unauthorized, (await client.SendAsync(revokedRequest)).StatusCode);

        var forgot = await client.PostAsJsonAsync("/api/v1/auth/forgot-password", new { email });
        Assert.Equal(System.Net.HttpStatusCode.Accepted, forgot.StatusCode);
        Assert.Equal(await unknownForgot.Content.ReadAsStringAsync(), await forgot.Content.ReadAsStringAsync());
        var supersededPin = await RequestAndReadPin();
        await ClearThrottleBuckets();
        _ = await RequestAndReadPin();
        Assert.Equal(System.Net.HttpStatusCode.BadRequest, (await client.PostAsJsonAsync("/api/v1/auth/verify-reset-code", new { email, code = supersededPin })).StatusCode);
        await ClearThrottleBuckets();
        var exhaustedPin = await RequestAndReadPin();
        var incorrectPin = int.Parse(exhaustedPin) == 999999 ? "000000" : (int.Parse(exhaustedPin) + 1).ToString("D6");
        for (var i = 0; i < 5; i++)
            Assert.Equal(System.Net.HttpStatusCode.BadRequest, (await client.PostAsJsonAsync("/api/v1/auth/verify-reset-code", new { email, code = incorrectPin })).StatusCode);
        Assert.Equal(System.Net.HttpStatusCode.BadRequest, (await client.PostAsJsonAsync("/api/v1/auth/verify-reset-code", new { email, code = exhaustedPin })).StatusCode);
        await ClearThrottleBuckets();
        var pin = await RequestAndReadPin();
        var exchanged = await client.PostAsJsonAsync("/api/v1/auth/verify-reset-code", new { email, code = pin });
        Assert.Equal(System.Net.HttpStatusCode.OK, exchanged.StatusCode);
        var resetToken = (await exchanged.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("resetToken").GetString()!;
        const string replacementPassword = "Second-Green-Passphrase-571!";
        var reset = await client.PostAsJsonAsync("/api/v1/auth/reset-password", new { resetToken, newPassword = replacementPassword });
        Assert.Equal(System.Net.HttpStatusCode.OK, reset.StatusCode);
        Assert.Equal(System.Net.HttpStatusCode.BadRequest, (await client.PostAsJsonAsync("/api/v1/auth/reset-password", new { resetToken, newPassword = "Fourth-Gray-Passphrase-347!" })).StatusCode);
        Assert.Equal(System.Net.HttpStatusCode.Unauthorized, (await client.PostAsJsonAsync("/api/v1/auth/login", new { email, password = initialPassword })).StatusCode);
        var replacementLogin = await client.PostAsJsonAsync("/api/v1/auth/login", new { email, password = replacementPassword });
        Assert.Equal(System.Net.HttpStatusCode.OK, replacementLogin.StatusCode);
        var replacementJson = await replacementLogin.Content.ReadFromJsonAsync<JsonElement>();
        var replacementAccess = replacementJson.GetProperty("accessToken").GetString()!;
        var replacementRefresh = Cookie(replacementLogin);
        using var wrongChangeRequest = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/change-password")
        {
            Content = JsonContent.Create(new { currentPassword = "Wrong-Current-Password-1!", newPassword = "Third-Orange-Passphrase-682!" })
        };
        wrongChangeRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", replacementAccess);
        Assert.Equal(System.Net.HttpStatusCode.BadRequest, (await client.SendAsync(wrongChangeRequest)).StatusCode);
        using var changeRequest = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/change-password")
        {
            Content = JsonContent.Create(new { currentPassword = replacementPassword, newPassword = "Third-Orange-Passphrase-682!" })
        };
        changeRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", replacementAccess);
        Assert.Equal(System.Net.HttpStatusCode.OK, (await client.SendAsync(changeRequest)).StatusCode);
        using var revokedAfterChange = Mutation("/api/v1/auth/refresh", replacementRefresh);
        Assert.Equal(System.Net.HttpStatusCode.Unauthorized, (await client.SendAsync(revokedAfterChange)).StatusCode);
        using var logout = Mutation("/api/v1/auth/logout", replacementRefresh);
        Assert.Equal(System.Net.HttpStatusCode.NoContent, (await client.SendAsync(logout)).StatusCode);

        async Task<string> RequestAndReadPin()
        {
            Assert.Equal(System.Net.HttpStatusCode.Accepted, (await client.PostAsJsonAsync("/api/v1/auth/forgot-password", new { email })).StatusCode);
            await using var db = new AuthDbContext(options);
            var rows = await db.EmailOutbox.OrderByDescending(x => x.CreatedAt).ToListAsync();
            var protector = app.Services.GetRequiredService<SecretPayloadProtector>();
            var message = rows.Select(x => protector.Unprotect<EmailSendRequested>(x.Nonce, x.Ciphertext, x.Tag)).First(x => x.TemplateKey == "auth-reset-password-pin");
            return message.TemplateData["pinGrouped"].Replace("-", "", StringComparison.Ordinal);
        }

        async Task ClearThrottleBuckets()
        {
            await using var db = new AuthDbContext(options);
            await db.ThrottleBuckets.ExecuteDeleteAsync();
        }
    }

    private static DistributedThrottle CreateThrottle(AuthDbContext db) => new(
        db,
        new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Throttle:HashKey"] = "test-only-hmac-key" }).Build(),
        TimeProvider.System);

    private static HttpRequestMessage Mutation(string path, string cookie)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, path);
        request.Headers.Add("Origin", "https://shop.example.test");
        request.Headers.Add("X-Requested-With", "XMLHttpRequest");
        request.Headers.Add("Cookie", cookie);
        return request;
    }

    private static string Cookie(HttpResponseMessage response) => response.Headers.GetValues("Set-Cookie").Single().Split(';')[0];

    private sealed class AuthApiFactory(string connectionString, string signingKey) : WebApplicationFactory<Program>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Testing");
            builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:Auth"] = connectionString,
                ["Jwt:PrivateKeyPem"] = signingKey,
                ["Jwt:KeyId"] = "test-key",
                ["Outbox:EncryptionKey"] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
                ["Pin:Pepper"] = "test-only-pin-pepper",
                ["Throttle:HashKey"] = "test-only-throttle-hash-key",
                ["RabbitMQ:Host"] = "127.0.0.1",
                ["RabbitMQ:Username"] = "test-user",
                ["RabbitMQ:Password"] = "test-password-only",
                ["RabbitMQ:EmailCommandQueue"] = "test-email-commands.v1",
                ["Cors:UiOrigin"] = "https://shop.example.test",
                ["CompareShopUI:BaseUrl"] = "https://shop.example.test",
                ["Turnstile:Enabled"] = "false"
            }));
        }
    }
}
