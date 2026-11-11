using System.Security.Cryptography;
using System.Text;
using CompareShopAuthAPI.Data;
using CompareShopAuthAPI.Security;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace CompareShopAuthAPI.Application;

public interface IVerifyEmailUseCase { Task<IResult> ExecuteAsync(HttpContext http, VerificationRequest request, CancellationToken cancellationToken); }
public sealed class VerifyEmailUseCase(AuthDbContext db, UserManager<AuthUser> users, TimeProvider clock) : IVerifyEmailUseCase
{
    public async Task<IResult> ExecuteAsync(HttpContext http, VerificationRequest request, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.Token)) return Results.BadRequest(new { code = "verification_invalid" });
        var email = request.Email.Trim();
        var tokenHash = AuthApplicationUtilities.Hash(request.Token);
        await using var transaction = await db.Database.BeginTransactionAsync(System.Data.IsolationLevel.Serializable, cancellationToken);
        var verification = await db.EmailVerifications.FromSqlInterpolated($"SELECT * FROM [EmailVerifications] WITH (UPDLOCK, HOLDLOCK) WHERE [TokenHash] = {tokenHash}").SingleOrDefaultAsync(cancellationToken);
        if (verification is null || verification.ExpiresAt <= clock.GetUtcNow() || verification.UsedAt is not null)
        {
            await transaction.RollbackAsync(cancellationToken);
            return Results.BadRequest(new { code = "verification_invalid" });
        }
        var user = await users.FindByIdAsync(verification.UserId);
        if (user is null || !string.Equals(user.Email, email, StringComparison.OrdinalIgnoreCase))
        {
            await transaction.RollbackAsync(cancellationToken);
            return Results.BadRequest(new { code = "verification_invalid" });
        }
        user.EmailConfirmed = true;
        verification.UsedAt = clock.GetUtcNow();
        db.AuthEvents.Add(AuthApplicationUtilities.NewEvent(user.Id, "email_verified", http));
        await db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return Results.Ok(new { message = "Email verified." });
    }
}

public interface IResendVerificationUseCase { Task<IResult> ExecuteAsync(HttpContext http, EmailRequest request, CancellationToken cancellationToken); }
public sealed class ResendVerificationUseCase(UserManager<AuthUser> users, AuthDbContext db, AuthEmailOutbox outbox, DistributedThrottle throttle, TurnstileVerifier captcha, TimeProvider clock, IConfiguration configuration, IHostEnvironment environment) : IResendVerificationUseCase
{
    public async Task<IResult> ExecuteAsync(HttpContext http, EmailRequest request, CancellationToken cancellationToken)
    {
        var captchaResult = await captcha.VerifyAsync(request.CaptchaToken, http.Connection.RemoteIpAddress?.ToString(), cancellationToken);
        if (!captchaResult.Accepted) return Results.BadRequest(new { code = "captcha_failed" });
        var generic = AuthApplicationUtilities.GenericEmailResponse();
        var ip = http.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var email = request.Email?.Trim() ?? "";
        var allowed = await throttle.TryConsumeAsync("resend:ip", ip, TestLimit("Throttle:ResendIpPerHour", 10), TimeSpan.FromHours(1), cancellationToken) &&
            await throttle.TryConsumeAsync("resend:email", email, TestLimit("Throttle:ResendEmailPerHour", 3), TimeSpan.FromHours(1), cancellationToken);
        if (!allowed) return Results.Accepted(value: generic);
        var user = await users.FindByEmailAsync(email);
        if (user is null || user.EmailConfirmed) return Results.Accepted(value: generic);
        await using var transaction = await db.Database.BeginTransactionAsync(System.Data.IsolationLevel.Serializable, cancellationToken);
        var now = clock.GetUtcNow();
        await db.EmailVerifications.Where(v => v.UserId == user.Id && v.UsedAt == null).ExecuteUpdateAsync(set => set.SetProperty(v => v.UsedAt, now), cancellationToken);
        var token = AuthApplicationUtilities.CreateSecret();
        db.EmailVerifications.Add(new EmailVerification { Id = Guid.NewGuid(), UserId = user.Id, TokenHash = AuthApplicationUtilities.Hash(token), ExpiresAt = now.AddHours(24) });
        var link = $"{configuration["CompareShopUI:BaseUrl"]?.TrimEnd('/')}/verify-email?email={Uri.EscapeDataString(user.Email!)}&token={Uri.EscapeDataString(token)}";
        outbox.Enqueue(user.Email!, "auth-verify", new Dictionary<string, string> { ["verificationLink"] = link });
        db.AuthEvents.Add(AuthApplicationUtilities.NewEvent(user.Id, "verification_resent", http));
        await db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return Results.Accepted(value: generic);
    }
    private int TestLimit(string key, int productionValue) => environment.IsEnvironment("Testing") ? configuration.GetValue(key, productionValue) : productionValue;
}

public interface IPasswordRecoveryUseCase
{
    Task<IResult> ForgotAsync(HttpContext http, EmailRequest request, CancellationToken cancellationToken);
    Task<IResult> VerifyCodeAsync(VerifyResetCodeRequest request, CancellationToken cancellationToken);
    Task<IResult> ResetAsync(HttpContext http, ResetPasswordRequest request, CancellationToken cancellationToken);
}

public sealed class PasswordRecoveryUseCase(UserManager<AuthUser> users, AuthDbContext db, AuthEmailOutbox outbox, DistributedThrottle throttle, TurnstileVerifier captcha, PasswordPolicy policy, IConfiguration configuration, TimeProvider clock, IHostEnvironment environment) : IPasswordRecoveryUseCase
{
    public async Task<IResult> ForgotAsync(HttpContext http, EmailRequest request, CancellationToken cancellationToken)
    {
        var captchaResult = await captcha.VerifyAsync(request.CaptchaToken, http.Connection.RemoteIpAddress?.ToString(), cancellationToken);
        if (!captchaResult.Accepted) return Results.BadRequest(new { code = "captcha_failed" });
        var generic = AuthApplicationUtilities.GenericEmailResponse();
        var ip = http.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var email = request.Email?.Trim() ?? "";
        var allowed = await throttle.TryConsumeAsync("forgot:ip", ip, TestLimit("Throttle:ForgotIpPerHour", 3), TimeSpan.FromHours(1), cancellationToken) &&
            await throttle.TryConsumeAsync("forgot:email", email, TestLimit("Throttle:ForgotEmailPerHour", 3), TimeSpan.FromHours(1), cancellationToken);
        if (!allowed) return Results.Accepted(value: generic);
        var user = await users.FindByEmailAsync(email);
        if (user is null || !user.EmailConfirmed) return Results.Accepted(value: generic);
        var now = clock.GetUtcNow();
        await using var transaction = await db.Database.BeginTransactionAsync(System.Data.IsolationLevel.Serializable, cancellationToken);
        await db.PasswordResetPins.Where(p => p.UserId == user.Id && p.UsedAt == null).ExecuteUpdateAsync(set => set.SetProperty(p => p.UsedAt, now), cancellationToken);
        var pin = RandomNumberGenerator.GetInt32(0, 1_000_000).ToString("D6");
        var salt = AuthApplicationUtilities.CreateSecret();
        db.PasswordResetPins.Add(new PasswordResetPin { Id = Guid.NewGuid(), UserId = user.Id, NormalizedEmail = users.NormalizeEmail(user.Email)!, PinSalt = salt, PinHash = AuthApplicationUtilities.PinHash(configuration, user.Id, salt, pin), CreatedAt = now, ExpiresAt = now.AddMinutes(10) });
        var pinData = new Dictionary<string, string> { ["displayName"] = "", ["expiresInMinutes"] = "10", ["pinSpaced"] = string.Join(' ', pin), ["pinGrouped"] = pin[..3] + "-" + pin[3..] };
        outbox.Enqueue(user.Email!, "auth-reset-password-pin", pinData);
        db.AuthEvents.Add(AuthApplicationUtilities.NewEvent(user.Id, "password_reset_requested", http));
        await db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return Results.Accepted(value: generic);
    }

    public async Task<IResult> VerifyCodeAsync(VerifyResetCodeRequest request, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.Code)) return Results.BadRequest(new { code = "reset_code_invalid" });
        var email = request.Email.Trim();
        var user = await users.FindByEmailAsync(email);
        if (user is null) return Results.BadRequest(new { code = "reset_code_invalid" });
        var normalized = users.NormalizeEmail(email);
        await using var transaction = await db.Database.BeginTransactionAsync(System.Data.IsolationLevel.Serializable, cancellationToken);
        var pin = await db.PasswordResetPins.FromSqlInterpolated($"SELECT TOP (1) * FROM [PasswordResetPins] WITH (UPDLOCK, HOLDLOCK) WHERE [NormalizedEmail] = {normalized} AND [UsedAt] IS NULL ORDER BY [CreatedAt] DESC").SingleOrDefaultAsync(cancellationToken);
        var now = clock.GetUtcNow();
        if (pin is null || pin.ExpiresAt <= now || pin.FailedAttempts >= 5)
        {
            await transaction.RollbackAsync(cancellationToken);
            return Results.BadRequest(new { code = "reset_code_invalid" });
        }
        if (!CryptographicOperations.FixedTimeEquals(Convert.FromHexString(pin.PinHash), Convert.FromHexString(AuthApplicationUtilities.PinHash(configuration, user.Id, pin.PinSalt, request.Code))))
        {
            pin.FailedAttempts++;
            if (pin.FailedAttempts >= 5) pin.UsedAt = now;
            await db.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return Results.BadRequest(new { code = "reset_code_invalid" });
        }
        var resetToken = AuthApplicationUtilities.CreateSecret();
        pin.UsedAt = now;
        db.PasswordResetGrants.Add(new PasswordResetGrant { Id = Guid.NewGuid(), UserId = user.Id, TokenHash = AuthApplicationUtilities.Hash(resetToken), ExpiresAt = now.AddMinutes(5) });
        await db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return Results.Ok(new { resetToken, expiresIn = 300 });
    }

    public async Task<IResult> ResetAsync(HttpContext http, ResetPasswordRequest request, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.ResetToken) || string.IsNullOrEmpty(request.NewPassword)) return Results.BadRequest(new { code = "reset_token_invalid" });
        var grantHash = AuthApplicationUtilities.Hash(request.ResetToken);
        await using var transaction = await db.Database.BeginTransactionAsync(System.Data.IsolationLevel.Serializable, cancellationToken);
        var grant = await db.PasswordResetGrants.FromSqlInterpolated($"SELECT * FROM [PasswordResetGrants] WITH (UPDLOCK, HOLDLOCK) WHERE [TokenHash] = {grantHash}").SingleOrDefaultAsync(cancellationToken);
        if (grant is null || grant.UsedAt is not null || grant.ExpiresAt <= clock.GetUtcNow())
        {
            await transaction.RollbackAsync(cancellationToken);
            return Results.BadRequest(new { code = "reset_token_invalid" });
        }
        var user = await users.FindByIdAsync(grant.UserId);
        if (user?.Email is null) { await transaction.RollbackAsync(cancellationToken); return Results.BadRequest(new { code = "reset_token_invalid" }); }
        var errors = policy.Validate(user.Email, request.NewPassword);
        if (errors.Count != 0) { await transaction.RollbackAsync(cancellationToken); return Results.ValidationProblem(errors); }
        var removed = await users.RemovePasswordAsync(user);
        var changed = removed.Succeeded ? await users.AddPasswordAsync(user, request.NewPassword) : removed;
        if (!changed.Succeeded)
        {
            await transaction.RollbackAsync(cancellationToken);
            return Results.ValidationProblem(changed.Errors.GroupBy(e => e.Code).ToDictionary(g => g.Key, g => g.Select(e => e.Description).ToArray()));
        }
        grant.UsedAt = clock.GetUtcNow();
        await db.RefreshSessions.Where(s => s.UserId == user.Id && s.RevokedAt == null).ExecuteUpdateAsync(set => set.SetProperty(s => s.RevokedAt, clock.GetUtcNow()), cancellationToken);
        db.AuthEvents.Add(AuthApplicationUtilities.NewEvent(user.Id, "password_reset_completed", http));
        await db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return Results.Ok(new { message = "Password updated." });
    }

    private int TestLimit(string key, int productionValue) => environment.IsEnvironment("Testing") ? configuration.GetValue(key, productionValue) : productionValue;
}

public interface IPasswordChangeUseCase { Task<IResult> ExecuteAsync(HttpContext http, ChangePasswordRequest request, CancellationToken cancellationToken); }
public sealed class PasswordChangeUseCase(UserManager<AuthUser> users, AuthDbContext db, AuthEmailOutbox outbox, PasswordPolicy policy, TimeProvider clock) : IPasswordChangeUseCase
{
    public async Task<IResult> ExecuteAsync(HttpContext http, ChangePasswordRequest request, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(request.CurrentPassword) || string.IsNullOrEmpty(request.NewPassword)) return Results.BadRequest(new { code = "password_change_failed" });
        var userId = http.User.FindFirst("sub")?.Value;
        if (string.IsNullOrWhiteSpace(userId)) return Results.Unauthorized();
        var user = await users.FindByIdAsync(userId);
        if (user?.Email is null) return Results.Unauthorized();
        var errors = policy.Validate(user.Email, request.NewPassword);
        if (errors.Count != 0) return Results.ValidationProblem(errors);
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        var result = await users.ChangePasswordAsync(user, request.CurrentPassword, request.NewPassword);
        if (!result.Succeeded)
        {
            await transaction.RollbackAsync(cancellationToken);
            return Results.BadRequest(new { code = "password_change_failed" });
        }
        await db.RefreshSessions.Where(s => s.UserId == user.Id && s.RevokedAt == null).ExecuteUpdateAsync(set => set.SetProperty(s => s.RevokedAt, clock.GetUtcNow()), cancellationToken);
        outbox.Enqueue(user.Email, "auth-password-changed", new Dictionary<string, string> { ["displayName"] = "" });
        db.AuthEvents.Add(AuthApplicationUtilities.NewEvent(user.Id, "password_changed", http));
        await db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return Results.Ok(new { message = "Password updated." });
    }
}

public interface IRefreshSessionUseCase
{
    Task<IResult> RefreshAsync(HttpContext http, CancellationToken cancellationToken);
    Task<IResult> LogoutAsync(HttpContext http, CancellationToken cancellationToken);
}

public sealed class RefreshSessionUseCase(AuthDbContext db, UserManager<AuthUser> users, AccessTokenIssuer issuer, TimeProvider clock, IConfiguration configuration) : IRefreshSessionUseCase
{
    public async Task<IResult> RefreshAsync(HttpContext http, CancellationToken cancellationToken)
    {
        if (!AuthApplicationUtilities.IsTrustedMutation(http, configuration)) return Results.StatusCode(403);
        var raw = http.Request.Cookies["__Secure-CS-Refresh"];
        if (string.IsNullOrEmpty(raw)) return Results.Unauthorized();
        var hash = AuthApplicationUtilities.Hash(raw);
        await using var rotation = await db.Database.BeginTransactionAsync(System.Data.IsolationLevel.Serializable, cancellationToken);
        var session = await db.RefreshSessions.FromSqlInterpolated($"SELECT * FROM [RefreshSessions] WITH (UPDLOCK, HOLDLOCK) WHERE [TokenHash] = {hash}").SingleOrDefaultAsync(cancellationToken);
        if (session is null) return Results.Unauthorized();
        var now = clock.GetUtcNow();
        if (session.RevokedAt is not null)
        {
            await db.RefreshSessions.Where(s => s.FamilyId == session.FamilyId && s.RevokedAt == null).ExecuteUpdateAsync(set => set.SetProperty(s => s.RevokedAt, now), cancellationToken);
            await rotation.CommitAsync(cancellationToken);
            AuthApplicationUtilities.ClearRefreshCookie(http);
            return Results.Unauthorized();
        }
        if (session.ExpiresAt <= now || session.FamilyExpiresAt <= now)
        {
            session.RevokedAt = now;
            await db.SaveChangesAsync(cancellationToken);
            await rotation.CommitAsync(cancellationToken);
            AuthApplicationUtilities.ClearRefreshCookie(http);
            return Results.Unauthorized();
        }
        if (!issuer.IsConfigured) return Results.Problem("Authentication is temporarily unavailable.", statusCode: StatusCodes.Status503ServiceUnavailable);
        var replacement = AuthApplicationUtilities.CreateSecret();
        var replacementHash = AuthApplicationUtilities.Hash(replacement);
        session.RevokedAt = now;
        session.ReplacedByHash = replacementHash;
        db.RefreshSessions.Add(new RefreshSession { Id = Guid.NewGuid(), FamilyId = session.FamilyId, UserId = session.UserId, TokenHash = replacementHash, CreatedAt = now, ExpiresAt = AuthApplicationUtilities.Min(now.AddDays(30), session.FamilyExpiresAt), FamilyExpiresAt = session.FamilyExpiresAt });
        await db.SaveChangesAsync(cancellationToken);
        var user = await users.FindByIdAsync(session.UserId);
        if (user is null) { await rotation.RollbackAsync(cancellationToken); AuthApplicationUtilities.ClearRefreshCookie(http); return Results.Unauthorized(); }
        await rotation.CommitAsync(cancellationToken);
        AuthApplicationUtilities.SetRefreshCookie(http, replacement);
        return Results.Ok(new { accessToken = issuer.Issue(user, now), tokenType = "Bearer", expiresIn = 900 });
    }

    public async Task<IResult> LogoutAsync(HttpContext http, CancellationToken cancellationToken)
    {
        if (!AuthApplicationUtilities.IsTrustedMutation(http, configuration)) return Results.StatusCode(403);
        var raw = http.Request.Cookies["__Secure-CS-Refresh"];
        if (!string.IsNullOrEmpty(raw))
        {
            var hash = AuthApplicationUtilities.Hash(raw);
            await db.RefreshSessions.Where(s => s.TokenHash == hash && s.RevokedAt == null).ExecuteUpdateAsync(set => set.SetProperty(s => s.RevokedAt, clock.GetUtcNow()), cancellationToken);
        }
        AuthApplicationUtilities.ClearRefreshCookie(http);
        return Results.NoContent();
    }
}

public static class AuthApplicationUtilities
{
    public static string CreateSecret() => Microsoft.AspNetCore.WebUtilities.WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
    public static string Hash(string raw) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(raw)));
    public static string PinHash(IConfiguration configuration, string userId, string salt, string pin)
    {
        var pepper = configuration["Pin:Pepper"];
        if (string.IsNullOrWhiteSpace(pepper)) throw new InvalidOperationException("PIN hashing secret is not configured.");
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(pepper));
        return Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes($"{userId}:{salt}:{pin}")));
    }
    public static AuthEvent NewEvent(string? userId, string type, HttpContext http) => new() { UserId = userId, Type = type, OccurredAt = DateTimeOffset.UtcNow, IpAddress = http.Connection.RemoteIpAddress?.ToString(), UserAgent = http.Request.Headers.UserAgent.ToString() };
    public static object GenericEmailResponse() => new { message = "If an eligible account exists, instructions will be sent." };
    public static DateTimeOffset Min(DateTimeOffset first, DateTimeOffset second) => first <= second ? first : second;
    public static bool IsTrustedMutation(HttpContext http, IConfiguration configuration)
    {
        var origin = configuration["Cors:UiOrigin"];
        return !string.IsNullOrWhiteSpace(origin) && http.Request.Headers.Origin == origin && http.Request.Headers["X-Requested-With"] == "XMLHttpRequest";
    }
    public static void SetRefreshCookie(HttpContext http, string value) => http.Response.Cookies.Append("__Secure-CS-Refresh", value, new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Strict, Path = "/api/v1/auth", Expires = DateTimeOffset.UtcNow.AddDays(30), IsEssential = true });
    public static void ClearRefreshCookie(HttpContext http) => http.Response.Cookies.Delete("__Secure-CS-Refresh", new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Strict, Path = "/api/v1/auth" });
}
