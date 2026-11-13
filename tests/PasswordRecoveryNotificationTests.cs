using CompareShopAuthAPI.Application;
using Xunit;

namespace CompareShopAuthAPI.Tests;

public sealed class PasswordRecoveryNotificationTests
{
    [Fact]
    public async Task SuccessfulResetEnqueuesCredentialFreeNotificationBeforeCommit()
    {
        var fixture = new ResetFixture();

        var response = await fixture.UseCase.ResetAsync(
            new AuthRequestContext("192.0.2.10", "test-agent"),
            new ResetPasswordRequest("one-time-reset-material", "A-strong-password-42"),
            CancellationToken.None);

        Assert.Equal(200, response.StatusCode);
        var notification = Assert.Single(fixture.Outbox.Messages);
        Assert.Equal("account@example.test", notification.Recipient);
        Assert.Equal("auth-password-changed", notification.Template);
        Assert.Equal(new Dictionary<string, string> { ["displayName"] = "" }, notification.Data);
        Assert.DoesNotContain("one-time-reset-material", string.Join(" ", notification.Data.Values));
        Assert.DoesNotContain("A-strong-password-42", string.Join(" ", notification.Data.Values));
        Assert.Equal(new[] { "begin", "revoke", "enqueue", "event", "save", "commit" }, fixture.Order);
        Assert.True(fixture.Transaction.Committed);
        Assert.False(fixture.Transaction.RolledBack);
    }

    [Fact]
    public async Task FailedPersistenceRollsBackResetAndNotificationTransaction()
    {
        var fixture = new ResetFixture { FailSave = true };

        await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.UseCase.ResetAsync(
            new AuthRequestContext("192.0.2.10", "test-agent"),
            new ResetPasswordRequest("one-time-reset-material", "A-strong-password-42"),
            CancellationToken.None));

        Assert.Single(fixture.Outbox.Messages);
        Assert.Equal(new[] { "begin", "revoke", "enqueue", "event", "save", "rollback" }, fixture.Order);
        Assert.False(fixture.Transaction.Committed);
        Assert.True(fixture.Transaction.RolledBack);
    }

    private sealed class ResetFixture
    {
        public List<string> Order { get; } = [];
        public FakeTransaction Transaction { get; }
        public FakeOutbox Outbox { get; }
        public bool FailSave { get; init; }
        public PasswordRecoveryUseCase UseCase { get; }

        public ResetFixture()
        {
            Transaction = new FakeTransaction(Order);
            Outbox = new FakeOutbox(Order);
            var data = new FakeData(Order, () => FailSave, Transaction);
            UseCase = new PasswordRecoveryUseCase(
                new FakeIdentity(), data, Outbox, new FakeThrottle(), new FakeCaptcha(), new PasswordPolicy(),
                new FakeSettings(), TimeProvider.System);
        }
    }

    private sealed class FakeTransaction(List<string> order) : IAuthTransaction
    {
        public bool Committed { get; private set; }
        public bool RolledBack { get; private set; }
        public Task CommitAsync(CancellationToken cancellationToken) { order.Add("commit"); Committed = true; return Task.CompletedTask; }
        public Task RollbackAsync(CancellationToken cancellationToken) { order.Add("rollback"); RolledBack = true; return Task.CompletedTask; }
        public ValueTask DisposeAsync()
        {
            if (!Committed && !RolledBack) { order.Add("rollback"); RolledBack = true; }
            return ValueTask.CompletedTask;
        }
    }

    private sealed class FakeOutbox(List<string> order) : IAuthEmailOutboxPort
    {
        public List<(string Recipient, string Template, Dictionary<string, string> Data)> Messages { get; } = [];
        public void Enqueue(string recipient, string template, Dictionary<string, string> data)
        { order.Add("enqueue"); Messages.Add((recipient, template, data)); }
    }

    private sealed class FakeIdentity : IAuthIdentityPort
    {
        public string? NormalizeEmail(string? email) => email?.ToUpperInvariant();
        public Task<AuthIdentityUser?> FindByEmailAsync(string email) => Task.FromResult<AuthIdentityUser?>(null);
        public Task<AuthIdentityUser?> FindByIdAsync(string userId) => Task.FromResult<AuthIdentityUser?>(new(userId, "account@example.test", true));
        public Task<AuthIdentityOperationResult> CreateAsync(string email, string password, CancellationToken cancellationToken) => throw new NotImplementedException();
        public Task<AuthPasswordCheckResult> CheckPasswordAsync(string userId, string password, bool lockoutOnFailure) => throw new NotImplementedException();
        public Task<AuthIdentityOperationResult> ConfirmEmailAsync(string userId) => throw new NotImplementedException();
        public Task<AuthIdentityOperationResult> ChangePasswordAsync(string userId, string currentPassword, string newPassword) => throw new NotImplementedException();
        public Task<AuthIdentityOperationResult> RemovePasswordAsync(string userId) => Task.FromResult(AuthIdentityOperationResult.Success);
        public Task<AuthIdentityOperationResult> AddPasswordAsync(string userId, string newPassword) => Task.FromResult(AuthIdentityOperationResult.Success);
    }

    private sealed class FakeData(List<string> order, Func<bool> failSave, FakeTransaction transaction) : IAuthDataPort
    {
        public Task<IAuthTransaction> BeginTransactionAsync(CancellationToken cancellationToken, bool serializable = true)
        { order.Add("begin"); return Task.FromResult<IAuthTransaction>(transaction); }
        public Task<EmailVerification?> FindEmailVerificationForUpdateAsync(string tokenHash, CancellationToken cancellationToken) => throw new NotImplementedException();
        public Task InvalidateEmailVerificationsAsync(string userId, DateTimeOffset usedAt, CancellationToken cancellationToken) => throw new NotImplementedException();
        public Task<PasswordResetPin?> FindLatestPasswordResetPinForUpdateAsync(string normalizedEmail, CancellationToken cancellationToken) => throw new NotImplementedException();
        public Task InvalidatePasswordResetPinsAsync(string userId, DateTimeOffset usedAt, CancellationToken cancellationToken) => throw new NotImplementedException();
        public Task<PasswordResetGrant?> FindPasswordResetGrantForUpdateAsync(string tokenHash, CancellationToken cancellationToken) => Task.FromResult<PasswordResetGrant?>(new() { Id = Guid.NewGuid(), UserId = "user-1", TokenHash = tokenHash, ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(5) });
        public Task<RefreshSession?> FindRefreshSessionForUpdateAsync(string tokenHash, CancellationToken cancellationToken) => throw new NotImplementedException();
        public Task RevokeRefreshFamilyAsync(Guid familyId, DateTimeOffset revokedAt, CancellationToken cancellationToken) => throw new NotImplementedException();
        public Task RevokeActiveRefreshSessionsAsync(string userId, DateTimeOffset revokedAt, CancellationToken cancellationToken) { order.Add("revoke"); return Task.CompletedTask; }
        public Task RevokeRefreshSessionAsync(string tokenHash, DateTimeOffset revokedAt, CancellationToken cancellationToken) => throw new NotImplementedException();
        public void Add(EmailVerification verification) => throw new NotImplementedException();
        public void Add(PasswordResetPin pin) => throw new NotImplementedException();
        public void Add(PasswordResetGrant grant) => throw new NotImplementedException();
        public void Add(RefreshSession session) => throw new NotImplementedException();
        public void Add(AuthEvent authEvent) => order.Add("event");
        public Task SaveChangesAsync(CancellationToken cancellationToken)
        { order.Add("save"); return failSave() ? Task.FromException(new InvalidOperationException("simulated persistence failure")) : Task.CompletedTask; }
    }

    private sealed class FakeThrottle : IAuthRateLimitPort
    { public Task<bool> TryConsumeAsync(string scope, string subject, int limit, TimeSpan window, CancellationToken cancellationToken) => Task.FromResult(true); }
    private sealed class FakeCaptcha : ICaptchaVerificationPort
    { public Task<CaptchaResult> VerifyAsync(string? token, string? remoteIp, CancellationToken cancellationToken) => Task.FromResult(new CaptchaResult(true)); }
    private sealed class FakeSettings : IAuthSettings
    {
        public string? Get(string key) => null;
        public bool GetBoolean(string key, bool defaultValue = false) => defaultValue;
        public int GetLimit(string key, int productionValue) => productionValue;
        public bool IsDevelopment => true;
    }
}
