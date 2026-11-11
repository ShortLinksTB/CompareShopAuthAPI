using System.Security.Cryptography;
using System.Text;
using CompareShopAuthAPI.Data;
using CompareShopAuthAPI.Security;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace CompareShopAuthAPI.Application;

public interface ILoginUseCase
{
    Task<IResult> ExecuteAsync(HttpContext http, LoginRequest request, CancellationToken cancellationToken);
}

public sealed class LoginUseCase(
    IAuthIdentityPort users,
    UnknownUserCredential unknownUser,
    AuthDbContext db,
    IAuthRateLimitPort throttle,
    AccessTokenIssuer issuer,
    ICaptchaVerificationPort captcha,
    TimeProvider clock,
    IConfiguration configuration,
    IHostEnvironment environment) : ILoginUseCase
{
    public async Task<IResult> ExecuteAsync(HttpContext http, LoginRequest request, CancellationToken cancellationToken)
    {
        var captchaResult = await captcha.VerifyAsync(request.CaptchaToken, http.Connection.RemoteIpAddress?.ToString(), cancellationToken);
        if (!captchaResult.Accepted) return Results.BadRequest(new { code = "captcha_failed" });
        var emailKey = request.Email?.Trim() ?? "";
        var password = request.Password ?? "";
        var ipKey = http.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var ipLimit = TestLimit("Throttle:LoginIpPer15Minutes", 10);
        var emailLimit = TestLimit("Throttle:LoginEmailPer15Minutes", 5);
        if (!await throttle.TryConsumeAsync("login:ip", ipKey, ipLimit, TimeSpan.FromMinutes(15), cancellationToken) ||
            !await throttle.TryConsumeAsync("login:email", emailKey, emailLimit, TimeSpan.FromMinutes(15), cancellationToken)) return Results.StatusCode(429);

        var normalized = users.NormalizeEmail(emailKey);
        var user = normalized is null ? null : await users.FindByEmailAsync(emailKey);
        if (user is null) unknownUser.Verify(password);
        var signInResult = user is null ? null : await users.CheckPasswordSignInAsync(user, password, lockoutOnFailure: true);
        if (signInResult?.IsLockedOut == true) unknownUser.Verify(password);
        if (signInResult?.Succeeded == true && user is not null && !user.EmailConfirmed)
        {
            db.AuthEvents.Add(NewEvent(user.Id, "login_failed", http));
            await db.SaveChangesAsync(cancellationToken);
            return Results.Json(new { code = "email_not_verified" }, statusCode: StatusCodes.Status403Forbidden);
        }
        if (signInResult?.Succeeded != true || user is null)
        {
            db.AuthEvents.Add(NewEvent(user?.Id, "login_failed", http));
            await db.SaveChangesAsync(cancellationToken);
            return Results.Json(new { code = "invalid_credentials" }, statusCode: StatusCodes.Status401Unauthorized);
        }

        db.AuthEvents.Add(NewEvent(user.Id, "login_succeeded", http));
        await db.SaveChangesAsync(cancellationToken);
        if (!issuer.IsConfigured) return Results.Problem("Authentication is temporarily unavailable.", statusCode: StatusCodes.Status503ServiceUnavailable);
        var refresh = CreateSecret();
        var now = clock.GetUtcNow();
        db.RefreshSessions.Add(new RefreshSession { Id = Guid.NewGuid(), FamilyId = Guid.NewGuid(), UserId = user.Id, TokenHash = Hash(refresh), CreatedAt = now, ExpiresAt = now.AddDays(30), FamilyExpiresAt = now.AddDays(90) });
        await db.SaveChangesAsync(cancellationToken);
        SetRefreshCookie(http, refresh);
        return Results.Ok(new { accessToken = issuer.Issue(user, now), tokenType = "Bearer", expiresIn = 900 });
    }

    private int TestLimit(string key, int productionValue) => environment.IsEnvironment("Testing") ? configuration.GetValue(key, productionValue) : productionValue;
    private static string CreateSecret() => Microsoft.AspNetCore.WebUtilities.WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
    private static string Hash(string raw) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(raw)));
    private static void SetRefreshCookie(HttpContext http, string value) => http.Response.Cookies.Append("__Secure-CS-Refresh", value, new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Strict, Path = "/api/v1/auth", Expires = DateTimeOffset.UtcNow.AddDays(30), IsEssential = true });
    private static AuthEvent NewEvent(string? userId, string type, HttpContext http) => new() { UserId = userId, Type = type, OccurredAt = DateTimeOffset.UtcNow, IpAddress = http.Connection.RemoteIpAddress?.ToString(), UserAgent = http.Request.Headers.UserAgent.ToString() };
}
