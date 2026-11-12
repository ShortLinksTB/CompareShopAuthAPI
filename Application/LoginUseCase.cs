using System.Security.Cryptography;
using System.Text;

namespace CompareShopAuthAPI.Application;

public interface ILoginUseCase
{
    Task<AuthResponse> ExecuteAsync(AuthRequestContext context, LoginRequest request, CancellationToken cancellationToken);
}

public sealed class LoginUseCase(
    IAuthIdentityPort users,
    IUnknownCredentialPort unknownUser,
    IAuthDataPort data,
    IAuthRateLimitPort throttle,
    IAccessTokenPort issuer,
    ICaptchaVerificationPort captcha,
    TimeProvider clock,
    IAuthSettings settings) : ILoginUseCase
{
    public async Task<AuthResponse> ExecuteAsync(AuthRequestContext context, LoginRequest request, CancellationToken cancellationToken)
    {
        var captchaResult = await captcha.VerifyAsync(request.CaptchaToken, context.RemoteIp, cancellationToken);
        if (!captchaResult.Accepted) return AuthResponses.BadRequest(new { code = "captcha_failed" });
        var emailKey = request.Email?.Trim() ?? "";
        var password = request.Password ?? "";
        var ipKey = context.RemoteIp ?? "unknown";
        if (!await throttle.TryConsumeAsync("login:ip", ipKey, settings.GetLimit("Throttle:LoginIpPer15Minutes", 10), TimeSpan.FromMinutes(15), cancellationToken) ||
            !await throttle.TryConsumeAsync("login:email", emailKey, settings.GetLimit("Throttle:LoginEmailPer15Minutes", 5), TimeSpan.FromMinutes(15), cancellationToken))
            return AuthResponses.TooManyRequests();

        var normalized = users.NormalizeEmail(emailKey);
        var user = normalized is null ? null : await users.FindByEmailAsync(emailKey);
        if (user is null) unknownUser.Verify(password);
        var signIn = user is null ? null : await users.CheckPasswordAsync(user.Id, password, lockoutOnFailure: true);
        if (signIn?.LockedOut == true) unknownUser.Verify(password);
        if (signIn?.Succeeded == true && user is not null && !user.EmailConfirmed)
        {
            data.Add(AuthApplicationUtilities.NewEvent(user.Id, "login_failed", context, clock.GetUtcNow()));
            await data.SaveChangesAsync(cancellationToken);
            return new AuthResponse(403, new { code = "email_not_verified" });
        }
        if (signIn?.Succeeded != true || user is null)
        {
            data.Add(AuthApplicationUtilities.NewEvent(user?.Id, "login_failed", context, clock.GetUtcNow()));
            await data.SaveChangesAsync(cancellationToken);
            return new AuthResponse(401, new { code = "invalid_credentials" });
        }

        data.Add(AuthApplicationUtilities.NewEvent(user.Id, "login_succeeded", context, clock.GetUtcNow()));
        await data.SaveChangesAsync(cancellationToken);
        if (!issuer.IsConfigured) return AuthResponses.Unavailable("Authentication is temporarily unavailable.");
        var refresh = AuthApplicationUtilities.CreateSecret();
        var now = clock.GetUtcNow();
        data.Add(new RefreshSession { Id = Guid.NewGuid(), FamilyId = Guid.NewGuid(), UserId = user.Id, TokenHash = Hash(refresh), CreatedAt = now, ExpiresAt = now.AddDays(30), FamilyExpiresAt = now.AddDays(90) });
        await data.SaveChangesAsync(cancellationToken);
        return new AuthResponse(200, new { accessToken = issuer.Issue(user, now), tokenType = "Bearer", expiresIn = 900 },
            new AuthCookie(refresh));
    }

    private static string Hash(string raw) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(raw)));
}
