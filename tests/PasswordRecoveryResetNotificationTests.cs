using CompareShopAuthAPI.Application;
using Xunit;

namespace CompareShopAuthAPI.Tests;

public sealed class PasswordRecoveryResetNotificationTests
{
    [Fact]
    public async Task SuccessfulResetQueuesCredentialFreeNotificationInsideTransaction()
    {
        var grant = new PasswordResetGrant
        {
            Id = Guid.NewGuid(),
            UserId = "user-id",
            TokenHash = "hashed-reset-token",
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(5)
        };
        var transaction = new RecordingTransaction();
        var data = new RecordingData(grant, transaction);
        var outbox = new RecordingOutbox(transaction);
        var users = new RecordingIdentity();
        var useCase = CreateUseCase(users, data, outbox);

        var response = await useCase.ResetAsync(new AuthRequestContext("127.0.0.1", "test"),
            new ResetPasswordRequest("opaque-reset-token", "A-new-secure-password-938!"), CancellationToken.None);

        Assert.Equal(200, response.StatusCode);
        var message = Assert.Single(outbox.Messages);
        Assert.Equal("account@example.test", message.Recipient);
        Assert.Equal("auth-password-changed", message.Template);
        Assert.Equal(new Dictionary<string, string> { ["displayName"] = "" }, message.Data);
        Assert.DoesNotContain(message.Data.Keys, key => key.Contains("password", StringComparison.OrdinalIgnoreCase) || key.Contains("token", StringComparison.OrdinalIgnoreCase) || key.Contains("reset", StringComparison.OrdinalIgnoreCase));
        Assert.True(data.RefreshSessionsRevoked);
        Assert.True(transaction.Committed);
        Assert.False(transaction.RolledBack);
        Assert.True(outbox.EnqueuedBeforeCommit);
    }

    [Fact]
    public async Task InvalidResetGrantDoesNotQueueNotification()
    {
        var transaction = new RecordingTransaction();
        var data = new RecordingData(null, transaction);
        var outbox = new RecordingOutbox(transaction);
        var useCase = CreateUseCase(new RecordingIdentity(), data, outbox);

        var response = await useCase.ResetAsync(new AuthRequestContext(null, null),
            new ResetPasswordRequest("opaque-reset-token", "A-new-secure-password-938!"), CancellationToken.None);

        Assert.Equal(400, response.StatusCode);
        Assert.Empty(outbox.Messages);
        Assert.True(transaction.RolledBack);
        Assert.False(transaction.Committed);
    }

    private static PasswordRecoveryUseCase CreateUseCase(RecordingIdentity users, RecordingData data, RecordingOutbox outbox) =>
        new(users, data, outbox, new AllowRateLimit(), new AcceptCaptcha(), new PasswordPolicy(), new TestSettings(), TimeProvider.System);

    private sealed class RecordingOutbox(RecordingTransaction transaction) : IAuthEmailOutboxPort
    {
        public List<(string Recipient, string Template, Dictionary<string, string> Data)> Messages { get; } = [];
        public bool EnqueuedBeforeCommit { get; private set; }

        public void Enqueue(string recipient, string template, Dictionary<string, string> data)
        {
            EnqueuedBeforeCommit = !transaction.Committed;
            Messages.Add((recipient, template, data));
        }
    }

    private sealed class RecordingTransaction : IAuthTransaction
    {
        public bool Committed { get; private set; }
        public bool RolledBack { get; private set; }
        public Task CommitAsync(CancellationToken cancellationToken) { Committed = true; return Task.CompletedTask; }
        public Task RollbackAsync(CancellationToken cancellationToken) { RolledBack = true; return Task.CompletedTask; }
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class RecordingData(PasswordResetGrant? grant, RecordingTransaction transaction) : IAuthDataPort
    {
        public bool RefreshSessionsRevoked { get; private set; }
        public Task<IAuthTransaction> BeginTransactionAsync(CancellationToken cancellationToken, bool serializable = true) => Task.FromResult<IAuthTransaction>(transaction);
        public Task<PasswordResetGrant?> FindPasswordResetGrantForUpdateAsync(string tokenHash, CancellationToken cancellationToken) => Task.FromResult(grant);
        public Task RevokeActiveRefreshSessionsAsync(string userId, DateTimeOffset revokedAt, CancellationToken cancellationToken) { RefreshSessionsRevoked = true; return Task.CompletedTask; }
        public void Add(AuthEvent authEvent) { }
        public Task SaveChangesAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<EmailVerification?> FindEmailVerificationForUpdateAsync(string tokenHash, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task InvalidateEmailVerificationsAsync(string userId, DateTimeOffset usedAt, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<PasswordResetPin?> FindLatestPasswordResetPinForUpdateAsync(string normalizedEmail, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task InvalidatePasswordResetPinsAsync(string userId, DateTimeOffset usedAt, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<RefreshSession?> FindRefreshSessionForUpdateAsync(string tokenHash, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task RevokeRefreshFamilyAsync(Guid familyId, DateTimeOffset revokedAt, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task RevokeRefreshSessionAsync(string tokenHash, DateTimeOffset revokedAt, CancellationToken cancellationToken) => throw new NotSupportedException();
        public void Add(EmailVerification verification) => throw new NotSupportedException();
        public void Add(PasswordResetPin pin) => throw new NotSupportedException();
        public void Add(PasswordResetGrant grant) => throw new NotSupportedException();
        public void Add(RefreshSession session) => throw new NotSupportedException();
    }

    private sealed class RecordingIdentity : IAuthIdentityPort
    {
        private readonly AuthIdentityUser user = new("user-id", "account@example.test", true);
        public Task<AuthIdentityUser?> FindByIdAsync(string userId) => Task.FromResult<AuthIdentityUser?>(user);
        public Task<AuthIdentityOperationResult> RemovePasswordAsync(string userId) => Task.FromResult(AuthIdentityOperationResult.Success);
        public Task<AuthIdentityOperationResult> AddPasswordAsync(string userId, string password) => Task.FromResult(AuthIdentityOperationResult.Success);
        public string? NormalizeEmail(string? email) => email?.ToUpperInvariant();
        public Task<AuthIdentityUser?> FindByEmailAsync(string email) => throw new NotSupportedException();
        public Task<AuthIdentityOperationResult> CreateAsync(string email, string password, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<AuthPasswordCheckResult> CheckPasswordAsync(string userId, string password, bool lockoutOnFailure) => throw new NotSupportedException();
        public Task<AuthIdentityOperationResult> ConfirmEmailAsync(string userId) => throw new NotSupportedException();
        public Task<AuthIdentityOperationResult> ChangePasswordAsync(string userId, string currentPassword, string newPassword) => throw new NotSupportedException();
    }

    private sealed class AllowRateLimit : IAuthRateLimitPort
    {
        public Task<bool> TryConsumeAsync(string scope, string subject, int limit, TimeSpan window, CancellationToken cancellationToken) => Task.FromResult(true);
    }

    private sealed class AcceptCaptcha : ICaptchaVerificationPort
    {
        public Task<CaptchaResult> VerifyAsync(string? token, string? remoteIp, CancellationToken cancellationToken) => Task.FromResult(new CaptchaResult(true));
    }

    private sealed class TestSettings : IAuthSettings
    {
        public string? Get(string key) => null;
        public bool GetBoolean(string key, bool defaultValue = false) => defaultValue;
        public int GetLimit(string key, int productionValue) => productionValue;
        public bool IsDevelopment => true;
    }
}
