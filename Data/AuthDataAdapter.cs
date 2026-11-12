using System.Data;
using CompareShopAuthAPI.Application;
using Microsoft.EntityFrameworkCore;

namespace CompareShopAuthAPI.Data;

public sealed class AuthDataAdapter(AuthDbContext db) : IAuthDataPort
{
    public async Task<IAuthTransaction> BeginTransactionAsync(CancellationToken cancellationToken, bool serializable = true) =>
        new EfAuthTransaction(serializable
            ? await db.Database.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken)
            : await db.Database.BeginTransactionAsync(cancellationToken));

    public Task<EmailVerification?> FindEmailVerificationForUpdateAsync(string tokenHash, CancellationToken ct) =>
        db.EmailVerifications.FromSqlInterpolated($"SELECT * FROM [EmailVerifications] WITH (UPDLOCK, HOLDLOCK) WHERE [TokenHash] = {tokenHash}").SingleOrDefaultAsync(ct);

    public async Task InvalidateEmailVerificationsAsync(string userId, DateTimeOffset usedAt, CancellationToken ct) =>
        _ = await db.EmailVerifications.Where(v => v.UserId == userId && v.UsedAt == null).ExecuteUpdateAsync(set => set.SetProperty(v => v.UsedAt, usedAt), ct);

    public Task<PasswordResetPin?> FindLatestPasswordResetPinForUpdateAsync(string normalizedEmail, CancellationToken ct) =>
        db.PasswordResetPins.FromSqlInterpolated($"SELECT TOP (1) * FROM [PasswordResetPins] WITH (UPDLOCK, HOLDLOCK) WHERE [NormalizedEmail] = {normalizedEmail} AND [UsedAt] IS NULL ORDER BY [CreatedAt] DESC").SingleOrDefaultAsync(ct);

    public async Task InvalidatePasswordResetPinsAsync(string userId, DateTimeOffset usedAt, CancellationToken ct) =>
        _ = await db.PasswordResetPins.Where(p => p.UserId == userId && p.UsedAt == null).ExecuteUpdateAsync(set => set.SetProperty(p => p.UsedAt, usedAt), ct);

    public Task<PasswordResetGrant?> FindPasswordResetGrantForUpdateAsync(string tokenHash, CancellationToken ct) =>
        db.PasswordResetGrants.FromSqlInterpolated($"SELECT * FROM [PasswordResetGrants] WITH (UPDLOCK, HOLDLOCK) WHERE [TokenHash] = {tokenHash}").SingleOrDefaultAsync(ct);

    public Task<RefreshSession?> FindRefreshSessionForUpdateAsync(string tokenHash, CancellationToken ct) =>
        db.RefreshSessions.FromSqlInterpolated($"SELECT * FROM [RefreshSessions] WITH (UPDLOCK, HOLDLOCK) WHERE [TokenHash] = {tokenHash}").SingleOrDefaultAsync(ct);

    public async Task RevokeRefreshFamilyAsync(Guid familyId, DateTimeOffset revokedAt, CancellationToken ct) =>
        _ = await db.RefreshSessions.Where(s => s.FamilyId == familyId && s.RevokedAt == null).ExecuteUpdateAsync(set => set.SetProperty(s => s.RevokedAt, revokedAt), ct);

    public async Task RevokeActiveRefreshSessionsAsync(string userId, DateTimeOffset revokedAt, CancellationToken ct) =>
        _ = await db.RefreshSessions.Where(s => s.UserId == userId && s.RevokedAt == null).ExecuteUpdateAsync(set => set.SetProperty(s => s.RevokedAt, revokedAt), ct);

    public async Task RevokeRefreshSessionAsync(string tokenHash, DateTimeOffset revokedAt, CancellationToken ct) =>
        _ = await db.RefreshSessions.Where(s => s.TokenHash == tokenHash && s.RevokedAt == null).ExecuteUpdateAsync(set => set.SetProperty(s => s.RevokedAt, revokedAt), ct);

    public void Add(EmailVerification verification) => db.EmailVerifications.Add(verification);
    public void Add(PasswordResetPin pin) => db.PasswordResetPins.Add(pin);
    public void Add(PasswordResetGrant grant) => db.PasswordResetGrants.Add(grant);
    public void Add(RefreshSession session) => db.RefreshSessions.Add(session);
    public void Add(AuthEvent authEvent) => db.AuthEvents.Add(authEvent);
    public Task SaveChangesAsync(CancellationToken cancellationToken) => db.SaveChangesAsync(cancellationToken);

    private sealed class EfAuthTransaction(Microsoft.EntityFrameworkCore.Storage.IDbContextTransaction transaction) : IAuthTransaction
    {
        public Task CommitAsync(CancellationToken cancellationToken) => transaction.CommitAsync(cancellationToken);
        public Task RollbackAsync(CancellationToken cancellationToken) => transaction.RollbackAsync(cancellationToken);
        public ValueTask DisposeAsync() => transaction.DisposeAsync();
    }
}
