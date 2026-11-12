using System.Security.Cryptography;
using System.Text;

namespace CompareShopAuthAPI.Application;

public interface IVerifyEmailUseCase { Task<AuthResponse> ExecuteAsync(AuthRequestContext context, VerificationRequest request, CancellationToken cancellationToken); }
public sealed class VerifyEmailUseCase(IAuthDataPort data, IAuthIdentityPort users, TimeProvider clock) : IVerifyEmailUseCase
{
    public async Task<AuthResponse> ExecuteAsync(AuthRequestContext context, VerificationRequest request, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.Token)) return AuthResponses.BadRequest(new { code = "verification_invalid" });
        await using var transaction = await data.BeginTransactionAsync(cancellationToken);
        var verification = await data.FindEmailVerificationForUpdateAsync(AuthApplicationUtilities.Hash(request.Token), cancellationToken);
        if (verification is null || verification.ExpiresAt <= clock.GetUtcNow() || verification.UsedAt is not null)
        {
            await transaction.RollbackAsync(cancellationToken);
            return AuthResponses.BadRequest(new { code = "verification_invalid" });
        }
        var user = await users.FindByIdAsync(verification.UserId);
        if (user is null || (!string.IsNullOrWhiteSpace(request.Email) && !string.Equals(user.Email, request.Email.Trim(), StringComparison.OrdinalIgnoreCase)))
        {
            await transaction.RollbackAsync(cancellationToken);
            return AuthResponses.BadRequest(new { code = "verification_invalid" });
        }
        var confirmed = await users.ConfirmEmailAsync(user.Id);
        if (!confirmed.Succeeded)
        {
            await transaction.RollbackAsync(cancellationToken);
            return AuthResponses.BadRequest(new { code = "verification_invalid" });
        }
        verification.UsedAt = clock.GetUtcNow();
        data.Add(AuthApplicationUtilities.NewEvent(user.Id, "email_verified", context, clock.GetUtcNow()));
        await data.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return AuthResponses.Ok(new { message = "Email verified." });
    }
}

public interface IResendVerificationUseCase { Task<AuthResponse> ExecuteAsync(AuthRequestContext context, EmailRequest request, CancellationToken cancellationToken); }
public sealed class ResendVerificationUseCase(IAuthIdentityPort users, IAuthDataPort data, IAuthEmailOutboxPort outbox, IAuthRateLimitPort throttle, ICaptchaVerificationPort captcha, TimeProvider clock, IAuthSettings settings) : IResendVerificationUseCase
{
    public async Task<AuthResponse> ExecuteAsync(AuthRequestContext context, EmailRequest request, CancellationToken cancellationToken)
    {
        var captchaResult = await captcha.VerifyAsync(request.CaptchaToken, context.RemoteIp, cancellationToken);
        if (!captchaResult.Accepted) return AuthResponses.BadRequest(new { code = "captcha_failed" });
        var generic = AuthApplicationUtilities.GenericEmailResponse();
        var ip = context.RemoteIp ?? "unknown";
        var email = request.Email?.Trim() ?? "";
        var allowed = await throttle.TryConsumeAsync("resend:ip", ip, settings.GetLimit("Throttle:ResendIpPerHour", 10), TimeSpan.FromHours(1), cancellationToken) &&
            await throttle.TryConsumeAsync("resend:email", email, settings.GetLimit("Throttle:ResendEmailPerHour", 3), TimeSpan.FromHours(1), cancellationToken);
        if (!allowed) return AuthResponses.Accepted(generic);
        var user = await users.FindByEmailAsync(email);
        if (user is null || user.EmailConfirmed) return AuthResponses.Accepted(generic);
        await using var transaction = await data.BeginTransactionAsync(cancellationToken);
        var now = clock.GetUtcNow();
        await data.InvalidateEmailVerificationsAsync(user.Id, now, cancellationToken);
        var token = AuthApplicationUtilities.CreateSecret();
        data.Add(new EmailVerification { Id = Guid.NewGuid(), UserId = user.Id, TokenHash = AuthApplicationUtilities.Hash(token), ExpiresAt = now.AddHours(24) });
        outbox.Enqueue(user.Email!, "auth-verify", AuthApplicationUtilities.VerificationTemplateData(token));
        data.Add(AuthApplicationUtilities.NewEvent(user.Id, "verification_resent", context, now));
        await data.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return AuthResponses.Accepted(generic);
    }
}

public interface IPasswordRecoveryUseCase
{
    Task<AuthResponse> ForgotAsync(AuthRequestContext context, EmailRequest request, CancellationToken cancellationToken);
    Task<AuthResponse> VerifyCodeAsync(VerifyResetCodeRequest request, CancellationToken cancellationToken);
    Task<AuthResponse> ResetAsync(AuthRequestContext context, ResetPasswordRequest request, CancellationToken cancellationToken);
}

public sealed class PasswordRecoveryUseCase(IAuthIdentityPort users, IAuthDataPort data, IAuthEmailOutboxPort outbox, IAuthRateLimitPort throttle, ICaptchaVerificationPort captcha, PasswordPolicy policy, IAuthSettings settings, TimeProvider clock) : IPasswordRecoveryUseCase
{
    public async Task<AuthResponse> ForgotAsync(AuthRequestContext context, EmailRequest request, CancellationToken cancellationToken)
    {
        var captchaResult = await captcha.VerifyAsync(request.CaptchaToken, context.RemoteIp, cancellationToken);
        if (!captchaResult.Accepted) return AuthResponses.BadRequest(new { code = "captcha_failed" });
        var generic = AuthApplicationUtilities.GenericEmailResponse();
        var ip = context.RemoteIp ?? "unknown";
        var email = request.Email?.Trim() ?? "";
        var allowed = await throttle.TryConsumeAsync("forgot:ip", ip, settings.GetLimit("Throttle:ForgotIpPerHour", 3), TimeSpan.FromHours(1), cancellationToken) &&
            await throttle.TryConsumeAsync("forgot:email", email, settings.GetLimit("Throttle:ForgotEmailPerHour", 3), TimeSpan.FromHours(1), cancellationToken);
        if (!allowed) return AuthResponses.Accepted(generic);
        var user = await users.FindByEmailAsync(email);
        if (user is null || !user.EmailConfirmed) return AuthResponses.Accepted(generic);
        var now = clock.GetUtcNow();
        await using var transaction = await data.BeginTransactionAsync(cancellationToken);
        await data.InvalidatePasswordResetPinsAsync(user.Id, now, cancellationToken);
        var pin = RandomNumberGenerator.GetInt32(0, 1_000_000).ToString("D6");
        var salt = AuthApplicationUtilities.CreateSecret();
        var normalized = users.NormalizeEmail(user.Email);
        if (normalized is null) throw new InvalidOperationException("Identity could not normalize the account email.");
        data.Add(new PasswordResetPin { Id = Guid.NewGuid(), UserId = user.Id, NormalizedEmail = normalized, PinSalt = salt, PinHash = AuthApplicationUtilities.PinHash(settings, user.Id, salt, pin), CreatedAt = now, ExpiresAt = now.AddMinutes(10) });
        var pinData = new Dictionary<string, string> { ["displayName"] = "", ["expiresInMinutes"] = "10", ["pinSpaced"] = string.Join(' ', pin), ["pinGrouped"] = pin[..3] + "-" + pin[3..] };
        outbox.Enqueue(user.Email!, "auth-reset-password-pin", pinData);
        data.Add(AuthApplicationUtilities.NewEvent(user.Id, "password_reset_requested", context, now));
        await data.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return AuthResponses.Accepted(generic);
    }

    public async Task<AuthResponse> VerifyCodeAsync(VerifyResetCodeRequest request, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.Code)) return AuthResponses.BadRequest(new { code = "reset_code_invalid" });
        var email = request.Email.Trim();
        var user = await users.FindByEmailAsync(email);
        if (user is null) return AuthResponses.BadRequest(new { code = "reset_code_invalid" });
        var normalized = users.NormalizeEmail(email);
        if (normalized is null) return AuthResponses.BadRequest(new { code = "reset_code_invalid" });
        await using var transaction = await data.BeginTransactionAsync(cancellationToken);
        var pin = await data.FindLatestPasswordResetPinForUpdateAsync(normalized, cancellationToken);
        var now = clock.GetUtcNow();
        if (pin is null || pin.ExpiresAt <= now || pin.FailedAttempts >= 5)
        {
            await transaction.RollbackAsync(cancellationToken);
            return AuthResponses.BadRequest(new { code = "reset_code_invalid" });
        }
        if (!CryptographicOperations.FixedTimeEquals(Convert.FromHexString(pin.PinHash), Convert.FromHexString(AuthApplicationUtilities.PinHash(settings, user.Id, pin.PinSalt, request.Code))))
        {
            pin.FailedAttempts++;
            if (pin.FailedAttempts >= 5) pin.UsedAt = now;
            await data.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return AuthResponses.BadRequest(new { code = "reset_code_invalid" });
        }
        var resetToken = AuthApplicationUtilities.CreateSecret();
        pin.UsedAt = now;
        data.Add(new PasswordResetGrant { Id = Guid.NewGuid(), UserId = user.Id, TokenHash = AuthApplicationUtilities.Hash(resetToken), ExpiresAt = now.AddMinutes(5) });
        await data.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return AuthResponses.Ok(new { resetToken, expiresIn = 300 });
    }

    public async Task<AuthResponse> ResetAsync(AuthRequestContext context, ResetPasswordRequest request, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.ResetToken) || string.IsNullOrEmpty(request.NewPassword)) return AuthResponses.BadRequest(new { code = "reset_token_invalid" });
        await using var transaction = await data.BeginTransactionAsync(cancellationToken);
        var grant = await data.FindPasswordResetGrantForUpdateAsync(AuthApplicationUtilities.Hash(request.ResetToken), cancellationToken);
        if (grant is null || grant.UsedAt is not null || grant.ExpiresAt <= clock.GetUtcNow())
        {
            await transaction.RollbackAsync(cancellationToken);
            return AuthResponses.BadRequest(new { code = "reset_token_invalid" });
        }
        var user = await users.FindByIdAsync(grant.UserId);
        if (user?.Email is null) { await transaction.RollbackAsync(cancellationToken); return AuthResponses.BadRequest(new { code = "reset_token_invalid" }); }
        var errors = policy.Validate(user.Email, request.NewPassword);
        if (errors.Count != 0) { await transaction.RollbackAsync(cancellationToken); return AuthResponses.ValidationProblem(errors); }
        var removed = await users.RemovePasswordAsync(user.Id);
        var changed = removed.Succeeded ? await users.AddPasswordAsync(user.Id, request.NewPassword) : removed;
        if (!changed.Succeeded)
        {
            await transaction.RollbackAsync(cancellationToken);
            return AuthResponses.ValidationProblem(changed.Errors.GroupBy(e => e.Code).ToDictionary(g => g.Key, g => g.Select(e => e.Description).ToArray()));
        }
        var now = clock.GetUtcNow();
        grant.UsedAt = now;
        await data.RevokeActiveRefreshSessionsAsync(user.Id, now, cancellationToken);
        data.Add(AuthApplicationUtilities.NewEvent(user.Id, "password_reset_completed", context, now));
        await data.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return AuthResponses.Ok(new { message = "Password updated." });
    }

}

public interface IPasswordChangeUseCase { Task<AuthResponse> ExecuteAsync(AuthRequestContext context, ChangePasswordRequest request, CancellationToken cancellationToken); }
public sealed class PasswordChangeUseCase(IAuthIdentityPort users, IAuthDataPort data, IAuthEmailOutboxPort outbox, PasswordPolicy policy, TimeProvider clock) : IPasswordChangeUseCase
{
    public async Task<AuthResponse> ExecuteAsync(AuthRequestContext context, ChangePasswordRequest request, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(request.CurrentPassword) || string.IsNullOrEmpty(request.NewPassword)) return AuthResponses.BadRequest(new { code = "password_change_failed" });
        var userId = context.UserId;
        if (string.IsNullOrWhiteSpace(userId)) return AuthResponses.Unauthorized();
        var user = await users.FindByIdAsync(userId);
        if (user?.Email is null) return AuthResponses.Unauthorized();
        var errors = policy.Validate(user.Email, request.NewPassword);
        if (errors.Count != 0) return AuthResponses.ValidationProblem(errors);
        await using var transaction = await data.BeginTransactionAsync(cancellationToken, serializable: false);
        var result = await users.ChangePasswordAsync(user.Id, request.CurrentPassword, request.NewPassword);
        if (!result.Succeeded)
        {
            await transaction.RollbackAsync(cancellationToken);
            return AuthResponses.BadRequest(new { code = "password_change_failed" });
        }
        var now = clock.GetUtcNow();
        await data.RevokeActiveRefreshSessionsAsync(user.Id, now, cancellationToken);
        outbox.Enqueue(user.Email, "auth-password-changed", new Dictionary<string, string> { ["displayName"] = "" });
        data.Add(AuthApplicationUtilities.NewEvent(user.Id, "password_changed", context, now));
        await data.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return AuthResponses.Ok(new { message = "Password updated." });
    }
}

public interface IRefreshSessionUseCase
{
    Task<AuthResponse> RefreshAsync(AuthRequestContext context, CancellationToken cancellationToken);
    Task<AuthResponse> LogoutAsync(AuthRequestContext context, CancellationToken cancellationToken);
}

public sealed class RefreshSessionUseCase(IAuthDataPort data, IAuthIdentityPort users, IAccessTokenPort issuer, TimeProvider clock, IAuthSettings settings) : IRefreshSessionUseCase
{
    public async Task<AuthResponse> RefreshAsync(AuthRequestContext context, CancellationToken cancellationToken)
    {
        if (!AuthApplicationUtilities.IsTrustedMutation(context, settings)) return AuthResponses.Forbidden();
        var raw = context.RefreshToken;
        if (string.IsNullOrEmpty(raw)) return AuthResponses.Unauthorized();
        await using var rotation = await data.BeginTransactionAsync(cancellationToken);
        var session = await data.FindRefreshSessionForUpdateAsync(AuthApplicationUtilities.Hash(raw), cancellationToken);
        if (session is null) return AuthResponses.Unauthorized();
        var now = clock.GetUtcNow();
        if (session.RevokedAt is not null)
        {
            await data.RevokeRefreshFamilyAsync(session.FamilyId, now, cancellationToken);
            await rotation.CommitAsync(cancellationToken);
            return new AuthResponse(401, null, new AuthCookie(null, Clear: true));
        }
        if (session.ExpiresAt <= now || session.FamilyExpiresAt <= now)
        {
            session.RevokedAt = now;
            await data.SaveChangesAsync(cancellationToken);
            await rotation.CommitAsync(cancellationToken);
            return new AuthResponse(401, null, new AuthCookie(null, Clear: true));
        }
        if (!issuer.IsConfigured) return AuthResponses.Unavailable("Authentication is temporarily unavailable.");
        var replacement = AuthApplicationUtilities.CreateSecret();
        var replacementHash = AuthApplicationUtilities.Hash(replacement);
        session.RevokedAt = now;
        session.ReplacedByHash = replacementHash;
        data.Add(new RefreshSession { Id = Guid.NewGuid(), FamilyId = session.FamilyId, UserId = session.UserId, TokenHash = replacementHash, CreatedAt = now, ExpiresAt = AuthApplicationUtilities.Min(now.AddDays(30), session.FamilyExpiresAt), FamilyExpiresAt = session.FamilyExpiresAt });
        await data.SaveChangesAsync(cancellationToken);
        var user = await users.FindByIdAsync(session.UserId);
        if (user is null) { await rotation.RollbackAsync(cancellationToken); return new AuthResponse(401, null, new AuthCookie(null, Clear: true)); }
        await rotation.CommitAsync(cancellationToken);
        return new AuthResponse(200, new { accessToken = issuer.Issue(user, now), tokenType = "Bearer", expiresIn = 900 }, new AuthCookie(replacement));
    }

    public async Task<AuthResponse> LogoutAsync(AuthRequestContext context, CancellationToken cancellationToken)
    {
        if (!AuthApplicationUtilities.IsTrustedMutation(context, settings)) return AuthResponses.Forbidden();
        var raw = context.RefreshToken;
        if (!string.IsNullOrEmpty(raw)) await data.RevokeRefreshSessionAsync(AuthApplicationUtilities.Hash(raw), clock.GetUtcNow(), cancellationToken);
        return new AuthResponse(204, null, new AuthCookie(null, Clear: true));
    }
}

public static class AuthApplicationUtilities
{
    public static string CreateSecret() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    public static Dictionary<string, string> VerificationTemplateData(string token) => new() { ["token"] = token };
    public static string Hash(string raw) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(raw)));
    public static string PinHash(IAuthSettings settings, string userId, string salt, string pin)
    {
        var pepper = settings.Get("Pin:Pepper");
        if (string.IsNullOrWhiteSpace(pepper)) throw new InvalidOperationException("PIN hashing secret is not configured.");
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(pepper));
        return Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes($"{userId}:{salt}:{pin}")));
    }
    public static AuthEvent NewEvent(string? userId, string type, AuthRequestContext context, DateTimeOffset now) =>
        new() { UserId = userId, Type = type, OccurredAt = now, IpAddress = context.RemoteIp, UserAgent = context.UserAgent };
    public static object GenericEmailResponse() => new { message = "If an eligible account exists, instructions will be sent." };
    public static DateTimeOffset Min(DateTimeOffset first, DateTimeOffset second) => first <= second ? first : second;
    public static bool IsTrustedMutation(AuthRequestContext context, IAuthSettings settings) =>
        !string.IsNullOrWhiteSpace(settings.Get("Cors:UiOrigin")) &&
        context.Origin == settings.Get("Cors:UiOrigin") && context.RequestedWith == "XMLHttpRequest";
}
