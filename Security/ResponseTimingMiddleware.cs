using System.Diagnostics;

namespace CompareShopAuthAPI.Security;

public sealed class ResponseTimingMiddleware(RequestDelegate next, IConfiguration configuration)
{
    private static readonly string[] ProtectedPaths =
    [
        "/api/v1/auth/register",
        "/api/v1/auth/forgot-password",
        "/api/v1/auth/login"
    ];

    public async Task InvokeAsync(HttpContext context)
    {
        var path = context.Request.Path.Value;
        if (path is null || !ProtectedPaths.Contains(path, StringComparer.OrdinalIgnoreCase))
        {
            await next(context);
            return;
        }

        var elapsed = Stopwatch.StartNew();
        await next(context);

        var minimumMs = Math.Max(0, configuration.GetValue("SecurityTiming:MinimumDurationMs", 250));
        var jitterMs = Math.Clamp(configuration.GetValue("SecurityTiming:JitterMs", 25), 0, 1000);
        var targetMs = minimumMs + (jitterMs == 0 ? 0 : Random.Shared.Next(0, jitterMs + 1));
        var remaining = TimeSpan.FromMilliseconds(targetMs) - elapsed.Elapsed;
        if (remaining > TimeSpan.Zero)
            await Task.Delay(remaining, context.RequestAborted);
    }
}
