using System.Text.Json;
using CompareShopAuthAPI.Security;
using Microsoft.EntityFrameworkCore;
using RabbitMQ.Client;

namespace CompareShopAuthAPI.Data;

public sealed class EmailOutboxPublisher(IServiceScopeFactory scopeFactory, IConfiguration configuration, SecretPayloadProtector protector, ILogger<EmailOutboxPublisher> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try { await PublishBatch(stoppingToken); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception ex) { logger.LogWarning("Email outbox publish attempt failed ({ExceptionType})", ex.GetType().Name); }
            await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);
        }
    }

    private async Task PublishBatch(CancellationToken ct)
    {
        var host = configuration["RabbitMQ:Host"];
        var username = configuration["RabbitMQ:Username"];
        var password = configuration["RabbitMQ:Password"];
        if (string.IsNullOrWhiteSpace(host) || string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
            throw new InvalidOperationException("RabbitMQ connection configuration is unavailable.");
        var factory = new ConnectionFactory { HostName = host, UserName = username, Password = password, AutomaticRecoveryEnabled = true, NetworkRecoveryInterval = TimeSpan.FromSeconds(5), RequestedConnectionTimeout = TimeSpan.FromSeconds(2) };
        await using var connection = await factory.CreateConnectionAsync(ct);
        await using var channel = await connection.CreateChannelAsync(
            new CreateChannelOptions(publisherConfirmationsEnabled: true, publisherConfirmationTrackingEnabled: true, null, null), ct);
        var queue = configuration["RabbitMQ:EmailCommandQueue"] ?? "email.send.requested.v1";
        await channel.QueueDeclareAsync(queue, durable: true, exclusive: false, autoDelete: false, arguments: null, cancellationToken: ct);

        await using var scope = scopeFactory.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        var now = DateTimeOffset.UtcNow;
        var rows = await db.EmailOutbox.FromSqlRaw("SELECT TOP (10) * FROM [EmailOutbox] WITH (UPDLOCK, READPAST, ROWLOCK) WHERE [PublishedAt] IS NULL AND [DeadLetteredAt] IS NULL AND [NextAttemptAt] <= {0} AND ([LeaseUntil] IS NULL OR [LeaseUntil] < {0}) ORDER BY [CreatedAt]", now).ToListAsync(ct);
        if (rows.Count == 0) return;
        foreach (var row in rows) { row.LeaseUntil = now.AddMinutes(1); row.Attempts++; }
        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);

        foreach (var row in rows)
        {
            try
            {
                var message = protector.Unprotect<EmailSendRequested>(row.Nonce, row.Ciphertext, row.Tag);
                var body = JsonSerializer.SerializeToUtf8Bytes(message);
                var props = new BasicProperties
                {
                    Persistent = true,
                    ContentType = "application/json",
                    MessageId = row.RequestId.ToString("D")
                };
                await channel.BasicPublishAsync(string.Empty, queue, mandatory: true, props, body, ct);
                row.PublishedAt = DateTimeOffset.UtcNow;
                row.LeaseUntil = null;
                row.LastError = null;
            }
            catch (Exception ex)
            {
                row.LeaseUntil = null;
                if (row.Attempts >= 20) row.DeadLetteredAt = DateTimeOffset.UtcNow;
                else row.NextAttemptAt = DateTimeOffset.UtcNow.AddSeconds(Math.Min(3600, Math.Pow(2, Math.Min(row.Attempts, 10))));
                row.LastError = ex.GetType().Name;
            }
        }
        await db.SaveChangesAsync(ct);
    }
}
