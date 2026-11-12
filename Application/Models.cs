namespace CompareShopAuthAPI.Application;

public sealed record RegisterRequest(string Email, string Password, string? CaptchaToken = null);
public sealed record LoginRequest(string Email, string Password, string? CaptchaToken = null);
public sealed record EmailRequest(string Email, string? CaptchaToken = null);
public sealed record VerificationRequest(string? Email, string Token);
public sealed record VerifyResetCodeRequest(string Email, string Code);
public sealed record ResetPasswordRequest(string ResetToken, string NewPassword);
public sealed record ChangePasswordRequest(string CurrentPassword, string NewPassword);

public sealed record AuthIdentityUser(string Id, string? Email, bool EmailConfirmed);
public sealed record AuthIdentityError(string Code, string Description);
public sealed record AuthIdentityOperationResult(bool Succeeded, IReadOnlyList<AuthIdentityError> Errors)
{
    public static AuthIdentityOperationResult Success { get; } = new(true, []);
}
public sealed record AuthPasswordCheckResult(bool Succeeded, bool LockedOut);
public sealed record CaptchaResult(bool Accepted, string? FailureCode = null);

public sealed record AuthRequestContext(
    string? RemoteIp,
    string? UserAgent,
    string? UserId = null,
    string? Origin = null,
    string? RequestedWith = null,
    string? RefreshToken = null);

public sealed record AuthCookie(string? Value, bool Clear = false);
public sealed record AuthResponse(int StatusCode, object? Body = null, AuthCookie? RefreshCookie = null);

public interface IAuthSettings
{
    string? Get(string key);
    bool GetBoolean(string key, bool defaultValue = false);
    int GetLimit(string key, int productionValue);
    bool IsDevelopment { get; }
}

public interface IAccessTokenPort
{
    bool IsConfigured { get; }
    string Issue(AuthIdentityUser user, DateTimeOffset now);
}

public interface IUnknownCredentialPort
{
    void Verify(string candidate);
}

public static class AuthResponses
{
    public static AuthResponse Ok(object? body = null) => new(200, body);
    public static AuthResponse Accepted(object? body = null) => new(202, body);
    public static AuthResponse NoContent() => new(204);
    public static AuthResponse BadRequest(object? body = null) => new(400, body);
    public static AuthResponse Unauthorized() => new(401);
    public static AuthResponse Forbidden() => new(403);
    public static AuthResponse TooManyRequests() => new(429);
    public static AuthResponse Unavailable(string detail) => new(503, new { title = detail });
    public static AuthResponse ValidationProblem(IDictionary<string, string[]> errors) => new(400, new ValidationProblemPayload(errors));
    public sealed record ValidationProblemPayload(IDictionary<string, string[]> Errors, string Type = "about:blank", string Title = "One or more validation errors occurred.", int Status = 400);
}

public sealed class RefreshSession
{
    public Guid Id { get; set; }
    public Guid FamilyId { get; set; }
    public string UserId { get; set; } = "";
    public string TokenHash { get; set; } = "";
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
    public string? ReplacedByHash { get; set; }
    public DateTimeOffset FamilyExpiresAt { get; set; }
}

public sealed class EmailVerification
{
    public Guid Id { get; set; }
    public string UserId { get; set; } = "";
    public string TokenHash { get; set; } = "";
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? UsedAt { get; set; }
}

public sealed class PasswordResetPin
{
    public Guid Id { get; set; }
    public string UserId { get; set; } = "";
    public string NormalizedEmail { get; set; } = "";
    public string PinHash { get; set; } = "";
    public string PinSalt { get; set; } = "";
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? UsedAt { get; set; }
    public int FailedAttempts { get; set; }
}

public sealed class PasswordResetGrant
{
    public Guid Id { get; set; }
    public string UserId { get; set; } = "";
    public string TokenHash { get; set; } = "";
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? UsedAt { get; set; }
}

public sealed class AuthEvent
{
    public long Id { get; set; }
    public string? UserId { get; set; }
    public string Type { get; set; } = "";
    public DateTimeOffset OccurredAt { get; set; }
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
}
