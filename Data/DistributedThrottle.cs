using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using CompareShopAuthAPI.Application;

namespace CompareShopAuthAPI.Data;

public sealed class DistributedThrottle(AuthDbContext db, IConfiguration configuration, TimeProvider clock) : IAuthRateLimitPort
{
    public async Task<bool> TryConsumeAsync(string category, string value, int limit, TimeSpan window, CancellationToken cancellationToken)
    {
        var pepper = configuration["Throttle:HashKey"];
        if (string.IsNullOrWhiteSpace(pepper)) throw new InvalidOperationException("Throttle key is not configured.");
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(pepper));
        var key = Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(category + ":" + value.Trim().ToUpperInvariant())));
        var now = clock.GetUtcNow();
        var seconds = (long)window.TotalSeconds;
        var windowStart = DateTimeOffset.FromUnixTimeSeconds(now.ToUnixTimeSeconds() / seconds * seconds);
        await using var transaction = await db.Database.BeginTransactionAsync(System.Data.IsolationLevel.Serializable, cancellationToken);
        var bucket = await db.ThrottleBuckets.FromSqlInterpolated($"SELECT * FROM [ThrottleBuckets] WITH (UPDLOCK, HOLDLOCK) WHERE [BucketKey] = {key} AND [WindowStart] = {windowStart}").SingleOrDefaultAsync(cancellationToken);
        if (bucket is null)
        {
            bucket = new ThrottleBucket { BucketKey = key, WindowStart = windowStart, Count = 1 };
            db.ThrottleBuckets.Add(bucket);
            await db.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return true;
        }
        if (bucket.Count >= limit)
        {
            await transaction.CommitAsync(cancellationToken);
            return false;
        }
        bucket.Count++;
        await db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return true;
    }
}
