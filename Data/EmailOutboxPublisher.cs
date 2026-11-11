using System.Text.Json;
using CompareShopAuthAPI.Security;
using Microsoft.EntityFrameworkCore;
using RabbitMQ.Client;

namespace CompareShopAuthAPI.Data;

public interface IEmailMessagePublisher
{
    Task PublishAsync(EmailSendRequested message, CancellationToken cancellationToken);
}

public sealed class EmailOutboxPublisher(IServiceScopeFactory scopeFactory, ILogger<EmailOutboxPublisher> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await using var scope = scopeFactory.CreateAsyncScope();
                await scope.ServiceProvider.GetRequiredService<EmailOutboxBatchDispatcher>().DispatchAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception ex) { logger.LogWarning("Email outbox publish attempt failed ({ExceptionType})", ex.GetType().Name); }
            await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);
        }
    }
}

public sealed class EmailOutboxBatchDispatcher(
    AuthDbContext db,
    SecretPayloadProtector protector,
    IEmailMessagePublisher publisher,
    TimeProvider clock,
    ILogger<EmailOutboxBatchDispatcher> logger)
{
    public async Task DispatchAsync(CancellationToken cancellationToken)
    {
        await using var tx = await db.Database.BeginTransactionAsync(cancellationToken);
        var now = clock.GetUtcNow();
        var rows = await db.EmailOutbox.FromSqlRaw(
            "SELECT TOP (10) * FROM [EmailOutbox] WITH (UPDLOCK, READPAST, ROWLOCK) WHERE [PublishedAt] IS NULL AND [DeadLetteredAt] IS NULL AND [NextAttemptAt] <= {0} AND ([LeaseUntil] IS NULL OR [LeaseUntil] < {0}) ORDER BY [CreatedAt]",
            now).ToListAsync(cancellationToken);
        if (rows.Count == 0) return;

        foreach (var row in rows)
        {
            row.LeaseUntil = now.AddMinutes(1);
            row.Attempts++;
        }
        await db.SaveChangesAsync(cancellationToken);
        await tx.CommitAsync(cancellationToken);

        foreach (var row in rows)
        {
            try
            {
                var message = protector.Unprotect<EmailSendRequested>(row.Nonce, row.Ciphertext, row.Tag);
                await publisher.PublishAsync(message, cancellationToken);
                row.PublishedAt = clock.GetUtcNow();
                row.LeaseUntil = null;
                row.LastError = null;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (Exception ex)
            {
                row.LeaseUntil = null;
                if (row.Attempts >= 20) row.DeadLetteredAt = clock.GetUtcNow();
                else row.NextAttemptAt = clock.GetUtcNow().AddSeconds(Math.Min(3600, Math.Pow(2, Math.Min(row.Attempts, 10))));
                row.LastError = ex.GetType().Name;
                logger.LogWarning("Email outbox request {RequestId} failed ({ExceptionType})", row.RequestId, ex.GetType().Name);
            }
        }
        await db.SaveChangesAsync(cancellationToken);
    }
}

public sealed class RabbitMqEmailMessagePublisher(IConfiguration configuration, ILogger<RabbitMqEmailMessagePublisher> logger) : IEmailMessagePublisher, IAsyncDisposable
{
    private readonly SemaphoreSlim gate = new(1, 1);
    private IConnection? connection;
    private IChannel? channel;

    public async Task PublishAsync(EmailSendRequested message, CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            await EnsureConnectedAsync(cancellationToken);
            var body = JsonSerializer.SerializeToUtf8Bytes(message);
            var properties = new BasicProperties
            {
                Persistent = true,
                ContentType = "application/json",
                MessageId = message.RequestId.ToString("D")
            };
            await channel!.BasicPublishAsync(string.Empty, QueueName(), mandatory: true, properties, body, cancellationToken);
        }
        catch
        {
            await ResetConnectionAsync();
            throw;
        }
        finally { gate.Release(); }
    }

    private async Task EnsureConnectedAsync(CancellationToken cancellationToken)
    {
        if (channel is not null && channel.IsOpen) return;
        var host = configuration["RabbitMQ:Host"];
        var username = configuration["RabbitMQ:Username"];
        var password = configuration["RabbitMQ:Password"];
        if (string.IsNullOrWhiteSpace(host) || string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
            throw new InvalidOperationException("RabbitMQ connection configuration is unavailable.");

        var factory = new ConnectionFactory
        {
            HostName = host,
            UserName = username,
            Password = password,
            AutomaticRecoveryEnabled = true,
            NetworkRecoveryInterval = TimeSpan.FromSeconds(5),
            RequestedConnectionTimeout = TimeSpan.FromSeconds(2)
        };
        connection = await factory.CreateConnectionAsync(cancellationToken);
        channel = await connection.CreateChannelAsync(
            new CreateChannelOptions(publisherConfirmationsEnabled: true, publisherConfirmationTrackingEnabled: true, null, null), cancellationToken);
        await channel.QueueDeclareAsync(QueueName(), durable: true, exclusive: false, autoDelete: false, arguments: null, cancellationToken: cancellationToken);
    }

    private string QueueName() => configuration["RabbitMQ:EmailCommandQueue"] ?? "email.send.requested.v1";

    private async Task ResetConnectionAsync()
    {
        try { if (channel is not null) await channel.DisposeAsync(); }
        catch (Exception ex) { logger.LogDebug("RabbitMQ channel cleanup failed ({ExceptionType})", ex.GetType().Name); }
        try { if (connection is not null) await connection.DisposeAsync(); }
        catch (Exception ex) { logger.LogDebug("RabbitMQ connection cleanup failed ({ExceptionType})", ex.GetType().Name); }
        channel = null;
        connection = null;
    }

    public async ValueTask DisposeAsync()
    {
        await gate.WaitAsync();
        try { await ResetConnectionAsync(); }
        finally
        {
            gate.Release();
            gate.Dispose();
        }
    }
}
