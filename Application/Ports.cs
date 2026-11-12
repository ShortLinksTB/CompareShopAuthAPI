namespace CompareShopAuthAPI.Application;

public interface IAuthIdentityPort
{
    string? NormalizeEmail(string? email);
    Task<AuthIdentityUser?> FindByEmailAsync(string email);
    Task<AuthIdentityUser?> FindByIdAsync(string userId);
    Task<AuthIdentityOperationResult> CreateAsync(string email, string password, CancellationToken cancellationToken);
    Task<AuthPasswordCheckResult> CheckPasswordAsync(string userId, string password, bool lockoutOnFailure);
    Task<AuthIdentityOperationResult> ConfirmEmailAsync(string userId);
    Task<AuthIdentityOperationResult> ChangePasswordAsync(string userId, string currentPassword, string newPassword);
    Task<AuthIdentityOperationResult> RemovePasswordAsync(string userId);
    Task<AuthIdentityOperationResult> AddPasswordAsync(string userId, string newPassword);
}

public interface IAuthRateLimitPort
{
    Task<bool> TryConsumeAsync(string scope, string subject, int limit, TimeSpan window, CancellationToken cancellationToken);
}

public interface IAuthEmailOutboxPort
{
    void Enqueue(string recipient, string template, Dictionary<string, string> data);
}

public interface ICaptchaVerificationPort
{
    Task<CaptchaResult> VerifyAsync(string? token, string? remoteIp, CancellationToken cancellationToken);
}

public interface IAuthDataPort
{
    Task<IAuthTransaction> BeginTransactionAsync(CancellationToken cancellationToken, bool serializable = true);
    Task<EmailVerification?> FindEmailVerificationForUpdateAsync(string tokenHash, CancellationToken cancellationToken);
    Task InvalidateEmailVerificationsAsync(string userId, DateTimeOffset usedAt, CancellationToken cancellationToken);
    Task<PasswordResetPin?> FindLatestPasswordResetPinForUpdateAsync(string normalizedEmail, CancellationToken cancellationToken);
    Task InvalidatePasswordResetPinsAsync(string userId, DateTimeOffset usedAt, CancellationToken cancellationToken);
    Task<PasswordResetGrant?> FindPasswordResetGrantForUpdateAsync(string tokenHash, CancellationToken cancellationToken);
    Task<RefreshSession?> FindRefreshSessionForUpdateAsync(string tokenHash, CancellationToken cancellationToken);
    Task RevokeRefreshFamilyAsync(Guid familyId, DateTimeOffset revokedAt, CancellationToken cancellationToken);
    Task RevokeActiveRefreshSessionsAsync(string userId, DateTimeOffset revokedAt, CancellationToken cancellationToken);
    Task RevokeRefreshSessionAsync(string tokenHash, DateTimeOffset revokedAt, CancellationToken cancellationToken);
    void Add(EmailVerification verification);
    void Add(PasswordResetPin pin);
    void Add(PasswordResetGrant grant);
    void Add(RefreshSession session);
    void Add(AuthEvent authEvent);
    Task SaveChangesAsync(CancellationToken cancellationToken);
}

public interface IAuthTransaction : IAsyncDisposable
{
    Task CommitAsync(CancellationToken cancellationToken);
    Task RollbackAsync(CancellationToken cancellationToken);
}
