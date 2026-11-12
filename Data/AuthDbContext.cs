using CompareShopAuthAPI.Application;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace CompareShopAuthAPI.Data;

public sealed class AuthDbContext(DbContextOptions<AuthDbContext> options) : IdentityDbContext<AuthUser>(options)
{
    public DbSet<AuthEvent> AuthEvents => Set<AuthEvent>();
    public DbSet<RefreshSession> RefreshSessions => Set<RefreshSession>();
    public DbSet<EmailVerification> EmailVerifications => Set<EmailVerification>();
    public DbSet<PasswordResetPin> PasswordResetPins => Set<PasswordResetPin>();
    public DbSet<PasswordResetGrant> PasswordResetGrants => Set<PasswordResetGrant>();
    public DbSet<EmailOutboxMessage> EmailOutbox => Set<EmailOutboxMessage>();
    public DbSet<ThrottleBucket> ThrottleBuckets => Set<ThrottleBucket>();
    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        builder.Entity<AuthEvent>().HasKey(e => e.Id);
        builder.Entity<EmailOutboxMessage>().HasKey(e => e.RequestId);
        builder.Entity<AuthEvent>().HasIndex(e => e.OccurredAt);
        builder.Entity<RefreshSession>().HasIndex(e => e.TokenHash).IsUnique();
        builder.Entity<RefreshSession>().HasIndex(e => new { e.FamilyId, e.RevokedAt });
        builder.Entity<EmailVerification>().HasIndex(e => e.TokenHash).IsUnique();
        builder.Entity<EmailVerification>().HasIndex(e => new { e.UserId, e.UsedAt });
        builder.Entity<PasswordResetPin>().HasIndex(e => e.NormalizedEmail);
        builder.Entity<PasswordResetPin>().HasIndex(e => new { e.UserId, e.UsedAt });
        builder.Entity<PasswordResetGrant>().HasIndex(e => e.TokenHash).IsUnique();
        builder.Entity<EmailOutboxMessage>().HasIndex(e => new { e.PublishedAt, e.NextAttemptAt });
        builder.Entity<ThrottleBucket>().HasIndex(e => new { e.BucketKey, e.WindowStart }).IsUnique();
    }
}

public sealed class EmailOutboxMessage
{
    public Guid RequestId { get; set; }
    public byte[] Nonce { get; set; } = [];
    public byte[] Ciphertext { get; set; } = [];
    public byte[] Tag { get; set; } = [];
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset NextAttemptAt { get; set; }
    public DateTimeOffset? LeaseUntil { get; set; }
    public DateTimeOffset? PublishedAt { get; set; }
    public DateTimeOffset? DeadLetteredAt { get; set; }
    public int Attempts { get; set; }
    public string? LastError { get; set; }
}

public sealed class ThrottleBucket
{
    public long Id { get; set; }
    public string BucketKey { get; set; } = "";
    public DateTimeOffset WindowStart { get; set; }
    public int Count { get; set; }
}
