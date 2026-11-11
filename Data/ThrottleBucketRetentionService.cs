using Microsoft.EntityFrameworkCore;

namespace CompareShopAuthAPI.Data;

public sealed class ThrottleBucketRetentionService(IServiceScopeFactory scopeFactory, ILogger<ThrottleBucketRetentionService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromHours(24));
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            try
            {
                await using var scope = scopeFactory.CreateAsyncScope();
                var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
                var cutoff = DateTimeOffset.UtcNow.AddDays(-30);
                await db.ThrottleBuckets.Where(bucket => bucket.WindowStart < cutoff).ExecuteDeleteAsync(stoppingToken);
                await db.EmailVerifications.Where(token => token.ExpiresAt < cutoff).ExecuteDeleteAsync(stoppingToken);
                await db.PasswordResetPins.Where(pin => pin.ExpiresAt < cutoff).ExecuteDeleteAsync(stoppingToken);
                await db.PasswordResetGrants.Where(grant => grant.ExpiresAt < cutoff).ExecuteDeleteAsync(stoppingToken);
                await db.RefreshSessions.Where(session => session.FamilyExpiresAt < cutoff).ExecuteDeleteAsync(stoppingToken);
                await db.EmailOutbox.Where(message => message.PublishedAt < cutoff).ExecuteDeleteAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception ex) { logger.LogWarning("Throttle bucket retention failed ({ExceptionType})", ex.GetType().Name); }
        }
    }
}
