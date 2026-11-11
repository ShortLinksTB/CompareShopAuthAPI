using System.Diagnostics;
using CompareShopAuthAPI.Security;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace CompareShopAuthAPI.Tests;

public sealed class ResponseTimingTests
{
    [Theory]
    [InlineData("/api/v1/auth/register")]
    [InlineData("/api/v1/auth/forgot-password")]
    [InlineData("/api/v1/auth/login")]
    public async Task SensitiveAccountEndpointResponsesMeetConfiguredMinimum(string path)
    {
        var middleware = CreateMiddleware();
        var elapsed = await Task.WhenAll(Enumerable.Range(0, 100).Select(async _ =>
        {
            var context = new DefaultHttpContext();
            context.Request.Path = path;
            var timer = Stopwatch.StartNew();
            await middleware.InvokeAsync(context);
            return timer.Elapsed;
        }));

        Assert.All(elapsed, duration => Assert.True(duration >= TimeSpan.FromMilliseconds(15), $"Response took {duration.TotalMilliseconds:F1} ms."));
    }

    [Fact]
    public async Task UnrelatedEndpointIsNotDelayed()
    {
        var middleware = CreateMiddleware();
        var context = new DefaultHttpContext();
        context.Request.Path = "/api/v1/auth/me";
        var timer = Stopwatch.StartNew();

        await middleware.InvokeAsync(context);

        Assert.True(timer.Elapsed < TimeSpan.FromMilliseconds(15));
    }

    private static ResponseTimingMiddleware CreateMiddleware() => new(
        _ => Task.CompletedTask,
        new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["SecurityTiming:MinimumDurationMs"] = "20",
            ["SecurityTiming:JitterMs"] = "0"
        }).Build());
}
