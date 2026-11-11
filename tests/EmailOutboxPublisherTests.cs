using System.Security.Cryptography;
using CompareShopAuthAPI.Data;
using CompareShopAuthAPI.Security;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Testcontainers.MsSql;
using Xunit;

namespace CompareShopAuthAPI.Tests;

public sealed class EmailOutboxPublisherTests : IAsyncLifetime
{
    private readonly MsSqlContainer sql = new MsSqlBuilder().WithPassword("Aa1!" + Convert.ToHexString(RandomNumberGenerator.GetBytes(16))).Build();
    private readonly string encryptionKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

    public Task InitializeAsync() => sql.StartAsync();
    public Task DisposeAsync() => sql.DisposeAsync().AsTask();

    [Fact]
    public async Task ConfirmedPublishMarksOutboxRowPublished()
    {
        await using (var db = CreateDb()) await db.Database.MigrateAsync();
        var expected = await AddOutboxMessage();
        var sender = new RecordingPublisher();

        await Dispatch(sender);

        await using var resultDb = CreateDb();
        var row = await resultDb.EmailOutbox.SingleAsync(x => x.RequestId == expected.RequestId);
        Assert.NotNull(row.PublishedAt);
        Assert.Null(row.LeaseUntil);
        Assert.Equal(1, row.Attempts);
        Assert.Equal(expected.RequestId, Assert.Single(sender.Messages).RequestId);
    }

    [Fact]
    public async Task FailedPublishSchedulesBackoffAndSuccessfulRetryMarksPublished()
    {
        await using (var db = CreateDb()) await db.Database.MigrateAsync();
        var expected = await AddOutboxMessage();
        var sender = new RecordingPublisher { FailNext = true };
        var before = DateTimeOffset.UtcNow;

        await Dispatch(sender);

        await using (var db = CreateDb())
        {
            var row = await db.EmailOutbox.SingleAsync(x => x.RequestId == expected.RequestId);
            Assert.Null(row.PublishedAt);
            Assert.Null(row.LeaseUntil);
            Assert.Equal(1, row.Attempts);
            Assert.Equal(nameof(HttpRequestException), row.LastError);
            Assert.InRange(row.NextAttemptAt, before.AddSeconds(1), DateTimeOffset.UtcNow.AddSeconds(10));
            row.NextAttemptAt = DateTimeOffset.UtcNow.AddSeconds(-1);
            await db.SaveChangesAsync();
        }

        await Dispatch(sender);

        await using var resultDb = CreateDb();
        var retried = await resultDb.EmailOutbox.SingleAsync(x => x.RequestId == expected.RequestId);
        Assert.NotNull(retried.PublishedAt);
        Assert.Equal(2, retried.Attempts);
        Assert.Equal(new[] { expected.RequestId, expected.RequestId }, sender.Messages.Select(x => x.RequestId));
    }

    [Fact]
    public async Task TwentiethFailedAttemptDeadLettersMessage()
    {
        await using (var db = CreateDb()) await db.Database.MigrateAsync();
        var expected = await AddOutboxMessage();
        await using (var db = CreateDb())
        {
            var row = await db.EmailOutbox.SingleAsync(x => x.RequestId == expected.RequestId);
            row.Attempts = 19;
            await db.SaveChangesAsync();
        }
        var sender = new RecordingPublisher { FailNext = true };

        await Dispatch(sender);

        await using var resultDb = CreateDb();
        var rowAfterFailure = await resultDb.EmailOutbox.SingleAsync(x => x.RequestId == expected.RequestId);
        Assert.Equal(20, rowAfterFailure.Attempts);
        Assert.NotNull(rowAfterFailure.DeadLetteredAt);
        Assert.Null(rowAfterFailure.PublishedAt);
    }

    private AuthDbContext CreateDb() => new(new DbContextOptionsBuilder<AuthDbContext>().UseSqlServer(sql.GetConnectionString()).Options);

    private async Task<EmailSendRequested> AddOutboxMessage()
    {
        var message = new EmailSendRequested(Guid.NewGuid(), 1, "person@example.test", "auth-verify", "vi", "auth-verify", new Dictionary<string, string> { ["verificationLink"] = "https://shop.example.test/verify?token=opaque" });
        var protector = CreateProtector();
        var encrypted = protector.Protect(message);
        var now = DateTimeOffset.UtcNow;
        await using var db = CreateDb();
        db.EmailOutbox.Add(new EmailOutboxMessage { RequestId = message.RequestId, Nonce = encrypted.Nonce, Ciphertext = encrypted.Ciphertext, Tag = encrypted.Tag, CreatedAt = now, NextAttemptAt = now });
        await db.SaveChangesAsync();
        return message;
    }

    private async Task Dispatch(RecordingPublisher publisher)
    {
        await using var db = CreateDb();
        var dispatcher = new EmailOutboxBatchDispatcher(db, CreateProtector(), publisher, TimeProvider.System, NullLogger<EmailOutboxBatchDispatcher>.Instance);
        await dispatcher.DispatchAsync(CancellationToken.None);
    }

    private SecretPayloadProtector CreateProtector() => new(new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
    {
        ["Outbox:EncryptionKey"] = encryptionKey
    }).Build());

    private sealed class RecordingPublisher : IEmailMessagePublisher
    {
        public bool FailNext { get; set; }
        public List<EmailSendRequested> Messages { get; } = [];

        public Task PublishAsync(EmailSendRequested message, CancellationToken cancellationToken)
        {
            Messages.Add(message);
            if (FailNext)
            {
                FailNext = false;
                throw new HttpRequestException("broker unavailable");
            }
            return Task.CompletedTask;
        }
    }
}
