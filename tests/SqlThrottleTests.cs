using System.Security.Cryptography;
using System.Net;
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
using System.Diagnostics;

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
        var unverifiedLogin = await client.PostAsJsonAsync("/api/v1/auth/login", new { email, password = initialPassword });
        Assert.Equal(System.Net.HttpStatusCode.Forbidden, unverifiedLogin.StatusCode);
        Assert.Equal("email_not_verified", (await unverifiedLogin.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("code").GetString());

        EmailSendRequested verifyMessage;
        await using (var db = new AuthDbContext(options))
        {
            var protector = app.Services.GetRequiredService<SecretPayloadProtector>();
            var rows = await db.EmailOutbox.OrderByDescending(x => x.CreatedAt).ToListAsync();
            verifyMessage = rows.Select(x => protector.Unprotect<EmailSendRequested>(x.Nonce, x.Ciphertext, x.Tag)).First(x => x.TemplateKey == "auth-verify");
        }
        Assert.Equal(new[] { "token" }, verifyMessage.TemplateData.Keys.Order().ToArray());
        var oldVerificationToken = verifyMessage.TemplateData["token"];
        Assert.Equal(System.Net.HttpStatusCode.Accepted, (await client.PostAsJsonAsync("/api/v1/auth/resend-verification", new { email })).StatusCode);
        await using (var db = new AuthDbContext(options))
        {
            var rows = await db.EmailOutbox.OrderByDescending(x => x.CreatedAt).ToListAsync();
            var protector = app.Services.GetRequiredService<SecretPayloadProtector>();
            verifyMessage = rows.Select(x => protector.Unprotect<EmailSendRequested>(x.Nonce, x.Ciphertext, x.Tag)).First(x => x.TemplateKey == "auth-verify");
        }
        Assert.Equal(new[] { "token" }, verifyMessage.TemplateData.Keys.Order().ToArray());
        var verificationToken = verifyMessage.TemplateData["token"];
        var renderedTarget = new Uri($"https://shop.example.test/verify-email?token={Uri.EscapeDataString(verificationToken)}");
        Assert.Equal("/verify-email", renderedTarget.AbsolutePath);
        Assert.Equal(verificationToken, renderedTarget.Query.Split('=', 2)[1]);
        Assert.Equal(System.Net.HttpStatusCode.BadRequest, (await client.PostAsJsonAsync("/api/v1/auth/verify-email", new { email, token = oldVerificationToken })).StatusCode);
        var verified = await client.PostAsJsonAsync("/api/v1/auth/verify-email", new { token = verificationToken });
        Assert.Equal(System.Net.HttpStatusCode.OK, verified.StatusCode);

        var knownWrongPassword = await client.PostAsJsonAsync("/api/v1/auth/login", new { email, password = "Wrong-Blue-Passphrase-994!" });
        Assert.Equal(System.Net.HttpStatusCode.Unauthorized, knownWrongPassword.StatusCode);
        Assert.Equal("invalid_credentials", (await knownWrongPassword.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("code").GetString());
        Assert.Equal(await unknownLogin.Content.ReadAsStringAsync(), await knownWrongPassword.Content.ReadAsStringAsync());

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

    [Fact]
    public async Task EnumerationCohortsHaveIdenticalResponsesAndBoundedTimingDeltas()
    {
        var options = new DbContextOptionsBuilder<AuthDbContext>().UseSqlServer(_sql.GetConnectionString()).Options;
        await using (var db = new AuthDbContext(options)) await db.Database.MigrateAsync();
        using var rsa = RSA.Create(2048);
        using var app = new AuthApiFactory(_sql.GetConnectionString(), rsa.ExportPkcs8PrivateKeyPem(), new Dictionary<string, string?>
        {
            ["SecurityTiming:MinimumDurationMs"] = "80",
            ["SecurityTiming:JitterMs"] = "25",
            ["Lockout:MaxFailedAccessAttempts"] = "200",
            ["Throttle:RegisterIpPerHour"] = "1000",
            ["Throttle:RegisterEmailPerHour"] = "1000",
            ["Throttle:LoginIpPer15Minutes"] = "1000",
            ["Throttle:LoginEmailPer15Minutes"] = "1000",
            ["Throttle:ForgotIpPerHour"] = "1000",
            ["Throttle:ForgotEmailPerHour"] = "1000"
        });
        using var client = app.CreateClient();
        var knownEmail = $"cohort-{Guid.NewGuid():N}@example.test";
        const string password = "Cohort-Blue-Passphrase-941!";

        Assert.Equal(System.Net.HttpStatusCode.Accepted, (await client.PostAsJsonAsync("/api/v1/auth/register", new { email = knownEmail, password })).StatusCode);
        var verificationMessage = await ReadLatestMessage("auth-verify");
        var token = verificationMessage.TemplateData["token"];
        Assert.Equal(System.Net.HttpStatusCode.OK, (await client.PostAsJsonAsync("/api/v1/auth/verify-email", new { token })).StatusCode);

        var newRegistration = await MeasureAsync(async index => await client.PostAsJsonAsync("/api/v1/auth/register", new { email = $"new-{index}-{Guid.NewGuid():N}@example.test", password }));
        var existingRegistration = await MeasureAsync(_ => client.PostAsJsonAsync("/api/v1/auth/register", new { email = knownEmail, password }));
        AssertEquivalentCohorts(newRegistration, existingRegistration);

        var unknownForgot = await MeasureAsync(_ => client.PostAsJsonAsync("/api/v1/auth/forgot-password", new { email = $"missing-{Guid.NewGuid():N}@example.test" }));
        var knownForgot = await MeasureAsync(_ => client.PostAsJsonAsync("/api/v1/auth/forgot-password", new { email = knownEmail }));
        AssertEquivalentCohorts(unknownForgot, knownForgot);

        var unknownLoginEmail = $"missing-{Guid.NewGuid():N}@example.test";
        var unknownLogin = await MeasureAsync(_ => client.PostAsJsonAsync("/api/v1/auth/login", new { email = unknownLoginEmail, password }));
        var knownWrongLogin = await MeasureAsync(_ => client.PostAsJsonAsync("/api/v1/auth/login", new { email = knownEmail, password = "Wrong-Cohort-Passphrase-941!" }));
        AssertEquivalentCohorts(unknownLogin, knownWrongLogin);

        async Task<CohortResult> MeasureAsync(Func<int, Task<HttpResponseMessage>> request)
        {
            var samples = new List<TimeSpan>(100);
            HttpStatusCode? expectedStatus = null;
            string? expectedBody = null;
            for (var i = 0; i < 100; i++)
            {
                var timer = Stopwatch.StartNew();
                using var response = await request(i);
                var body = await response.Content.ReadAsStringAsync();
                timer.Stop();
                if (expectedStatus is null)
                {
                    expectedStatus = response.StatusCode;
                    expectedBody = body;
                }
                else
                {
                    Assert.Equal(expectedStatus, response.StatusCode);
                    Assert.Equal(expectedBody, body);
                }
                samples.Add(timer.Elapsed);
            }
            return new CohortResult(samples, expectedStatus!.Value, expectedBody!);
        }

        async Task<EmailSendRequested> ReadLatestMessage(string template)
        {
            await using var db = new AuthDbContext(options);
            var protector = app.Services.GetRequiredService<SecretPayloadProtector>();
            var rows = await db.EmailOutbox.OrderByDescending(x => x.CreatedAt).ToListAsync();
            return rows.Select(x => protector.Unprotect<EmailSendRequested>(x.Nonce, x.Ciphertext, x.Tag)).First(x => x.TemplateKey == template);
        }
    }

    private static void AssertEquivalentCohorts(CohortResult left, CohortResult right)
    {
        Assert.Equal(left.Status, right.Status);
        Assert.Equal(left.Body, right.Body);
        Assert.InRange((Percentile(left.Samples, 0.50) - Percentile(right.Samples, 0.50)).Duration().TotalMilliseconds, 0d, 25d);
        Assert.InRange((Percentile(left.Samples, 0.95) - Percentile(right.Samples, 0.95)).Duration().TotalMilliseconds, 0d, 50d);
    }

    private static TimeSpan Percentile(IReadOnlyCollection<TimeSpan> samples, double percentile)
    {
        var ordered = samples.OrderBy(x => x).ToArray();
        var index = Math.Clamp((int)Math.Ceiling(percentile * ordered.Length) - 1, 0, ordered.Length - 1);
        return ordered[index];
    }

    private sealed record CohortResult(IReadOnlyCollection<TimeSpan> Samples, System.Net.HttpStatusCode Status, string Body);

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

    private sealed class AuthApiFactory(string connectionString, string signingKey, Dictionary<string, string?>? extraSettings = null) : WebApplicationFactory<Program>
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
            }.Concat(extraSettings ?? []).ToDictionary(x => x.Key, x => x.Value)));
        }
    }
}
