using System.Security.Claims;
using CompareShopAuthAPI.Application;
using CompareShopAuthAPI.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace CompareShopAuthAPI.Tests;

public sealed class AuthEndpointAdapterTests
{
    [Fact]
    public void ApplicationResponseFactoriesPreserveStatusCodes()
    {
        Assert.Equal(StatusCodes.Status401Unauthorized, AuthResponses.Unauthorized().StatusCode);
        Assert.Equal(StatusCodes.Status403Forbidden, AuthResponses.Forbidden().StatusCode);
        Assert.Equal(StatusCodes.Status429TooManyRequests, AuthResponses.TooManyRequests().StatusCode);
        Assert.True(AuthIdentityOperationResult.Success.Succeeded);
        Assert.Empty(AuthIdentityOperationResult.Success.Errors);
        Assert.Equal(0, new AuthEvent().Id);
    }

    [Fact]
    public void ReadContextMapsRequestMetadataAndPrefersSubjectClaim()
    {
        var context = CreateContext();
        context.Connection.RemoteIpAddress = System.Net.IPAddress.Loopback;
        context.Request.Headers.UserAgent = "test-agent";
        context.Request.Headers.Origin = "https://shop.example";
        context.Request.Headers["X-Requested-With"] = "XMLHttpRequest";
        context.Request.Headers.Cookie = "__Secure-CS-Refresh=refresh-token";
        context.User = new ClaimsPrincipal(new ClaimsIdentity([
            new Claim("sub", "subject-id"),
            new Claim(ClaimTypes.NameIdentifier, "name-id")
        ], "test"));

        var request = AuthEndpointAdapter.ReadContext(context);

        Assert.Equal("127.0.0.1", request.RemoteIp);
        Assert.Equal("test-agent", request.UserAgent);
        Assert.Equal("subject-id", request.UserId);
        Assert.Equal("https://shop.example", request.Origin);
        Assert.Equal("XMLHttpRequest", request.RequestedWith);
        Assert.Equal("refresh-token", request.RefreshToken);
    }

    [Fact]
    public async Task ToHttpResultMapsEmptyJsonValidationAndUnavailableResponses()
    {
        var context = CreateContext();

        var empty = AuthEndpointAdapter.ToHttpResult(context, AuthResponses.NoContent());
        await empty.ExecuteAsync(context);
        Assert.Equal(StatusCodes.Status204NoContent, context.Response.StatusCode);

        context = CreateContext();
        var json = AuthEndpointAdapter.ToHttpResult(context, AuthResponses.Ok(new { value = "ok" }));
        await json.ExecuteAsync(context);
        Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);
        Assert.Contains("application/json", context.Response.ContentType);

        context = CreateContext();
        var validation = AuthEndpointAdapter.ToHttpResult(context,
            AuthResponses.ValidationProblem(new Dictionary<string, string[]> { ["email"] = ["invalid"] }));
        await validation.ExecuteAsync(context);
        Assert.Equal(StatusCodes.Status400BadRequest, context.Response.StatusCode);

        context = CreateContext();
        var unavailable = AuthEndpointAdapter.ToHttpResult(context, AuthResponses.Unavailable("temporarily down"));
        Assert.Equal(StatusCodes.Status503ServiceUnavailable,
            Assert.IsAssignableFrom<IStatusCodeHttpResult>(unavailable).StatusCode);
        Assert.Equal("temporarily down", Assert.IsAssignableFrom<IValueHttpResult>(unavailable).Value is ProblemDetails details ? details.Detail : null);

        context = CreateContext();
        var fallback = AuthEndpointAdapter.ToHttpResult(context,
            new AuthResponse(StatusCodes.Status503ServiceUnavailable, new { detail = "missing title" }));
        Assert.Equal(StatusCodes.Status503ServiceUnavailable,
            Assert.IsAssignableFrom<IStatusCodeHttpResult>(fallback).StatusCode);
    }

    [Fact]
    public void ToHttpResultSetsAndDeletesRefreshCookie()
    {
        var context = CreateContext();
        _ = AuthEndpointAdapter.ToHttpResult(context,
            new AuthResponse(StatusCodes.Status200OK, RefreshCookie: new AuthCookie("opaque-token")));
        Assert.Contains("__Secure-CS-Refresh=opaque-token", context.Response.Headers.SetCookie.ToString());
        Assert.Contains("httponly", context.Response.Headers.SetCookie.ToString(), StringComparison.OrdinalIgnoreCase);

        context = CreateContext();
        _ = AuthEndpointAdapter.ToHttpResult(context,
            new AuthResponse(StatusCodes.Status200OK, RefreshCookie: new AuthCookie(null, Clear: true)));
        Assert.Contains("__Secure-CS-Refresh=", context.Response.Headers.SetCookie.ToString());
        Assert.Contains("expires=", context.Response.Headers.SetCookie.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    private static DefaultHttpContext CreateContext()
    {
        var context = new DefaultHttpContext
        {
            RequestServices = new ServiceCollection().AddLogging().BuildServiceProvider()
        };
        context.Response.Body = new MemoryStream();
        return context;
    }
}
