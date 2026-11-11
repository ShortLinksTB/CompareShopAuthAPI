using System.Security.Cryptography;
using System.Text;
using CompareShopAuthAPI.Data;
using CompareShopAuthAPI.Security;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace CompareShopAuthAPI.Application;

public interface IRegisterAccountUseCase
{
    Task<IResult> ExecuteAsync(HttpContext http, RegisterRequest request, CancellationToken cancellationToken);
}

public sealed class RegisterAccountUseCase(
    UserManager<AuthUser> users,
    AuthDbContext db,
    AuthEmailOutbox outbox,
    DistributedThrottle throttle,
    PasswordPolicy policy,
    TurnstileVerifier captcha,
    TimeProvider clock,
    IConfiguration configuration,
    IHostEnvironment environment) : IRegisterAccountUseCase
{
    public async Task<IResult> ExecuteAsync(HttpContext http, RegisterRequest request, CancellationToken cancellationToken)
    {
        var captchaResult = await captcha.VerifyAsync(request.CaptchaToken, http.Connection.RemoteIpAddress?.ToString(), cancellationToken);
        if (!captchaResult.Accepted) return Results.BadRequest(new { code = "captcha_failed" });
        if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrEmpty(request.Password))
            return Results.ValidationProblem(new Dictionary<string, string[]> { ["request"] = ["Email and password are required."] });

        var email = request.Email.Trim();
        var ip = http.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var registerIpLimit = TestLimit("Throttle:RegisterIpPerHour", 10);
        var registerEmailLimit = TestLimit("Throttle:RegisterEmailPerHour", 5);
        if (!await throttle.TryConsumeAsync("register:ip", ip, registerIpLimit, TimeSpan.FromHours(1), cancellationToken) ||
            !await throttle.TryConsumeAsync("register:email", email, registerEmailLimit, TimeSpan.FromHours(1), cancellationToken)) return Results.StatusCode(429);
        var errors = policy.Validate(email, request.Password);
        if (errors.Count != 0) return Results.ValidationProblem(errors);

        var user = new AuthUser { UserName = email, Email = email, EmailConfirmed = false };
        await using var transaction = await db.Database.BeginTransactionAsync(System.Data.IsolationLevel.Serializable, cancellationToken);
        var result = await users.CreateAsync(user, request.Password);
        if (!result.Succeeded)
        {
            await transaction.RollbackAsync(cancellationToken);
            if (result.Errors.Any(e => e.Code == "DuplicateUserName" || e.Code == "DuplicateEmail"))
            {
                outbox.Enqueue(email, "auth-existing-account", new Dictionary<string, string> { ["displayName"] = "" });
                await db.SaveChangesAsync(cancellationToken);
                return Results.Accepted(value: GenericEmailResponse());
            }
            return Results.ValidationProblem(result.Errors.GroupBy(e => e.Code).ToDictionary(g => g.Key, g => g.Select(e => e.Description).ToArray()));
        }

        var rawToken = CreateSecret();
        db.EmailVerifications.Add(new EmailVerification { Id = Guid.NewGuid(), UserId = user.Id, TokenHash = Hash(rawToken), ExpiresAt = clock.GetUtcNow().AddHours(24) });
        var link = $"{configuration["CompareShopUI:BaseUrl"]?.TrimEnd('/')}/verify-email?email={Uri.EscapeDataString(email)}&token={Uri.EscapeDataString(rawToken)}";
        outbox.Enqueue(email, "auth-verify", new Dictionary<string, string> { ["verificationLink"] = link });
        db.AuthEvents.Add(NewEvent(user.Id, "registered", http));
        await db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return Results.Accepted(value: GenericEmailResponse());
    }

    private int TestLimit(string key, int productionValue) => environment.IsEnvironment("Testing") ? configuration.GetValue(key, productionValue) : productionValue;
    private static string CreateSecret() => Microsoft.AspNetCore.WebUtilities.WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
    private static string Hash(string raw) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(raw)));
    private static object GenericEmailResponse() => new { message = "If an eligible account exists, instructions will be sent." };
    private static AuthEvent NewEvent(string userId, string type, HttpContext http) => new() { UserId = userId, Type = type, OccurredAt = DateTimeOffset.UtcNow, IpAddress = http.Connection.RemoteIpAddress?.ToString(), UserAgent = http.Request.Headers.UserAgent.ToString() };
}
