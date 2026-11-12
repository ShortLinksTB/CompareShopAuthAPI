using System.Security.Claims;
using CompareShopAuthAPI.Application;
using Microsoft.AspNetCore.Http;

namespace CompareShopAuthAPI.Http;

public static class AuthEndpointAdapter
{
    public static AuthRequestContext ReadContext(HttpContext context) => new(
        context.Connection.RemoteIpAddress?.ToString(),
        context.Request.Headers.UserAgent.ToString(),
        context.User.FindFirst("sub")?.Value ?? context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value,
        context.Request.Headers.Origin.ToString(),
        context.Request.Headers["X-Requested-With"].ToString(),
        context.Request.Cookies["__Secure-CS-Refresh"]);

    public static IResult ToHttpResult(HttpContext context, AuthResponse response)
    {
        if (response.RefreshCookie is { } cookie)
        {
            var options = new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Path = "/api/v1/auth",
                IsEssential = true
            };
            if (cookie.Clear)
                context.Response.Cookies.Delete("__Secure-CS-Refresh", options);
            else
            {
                options.Expires = DateTimeOffset.UtcNow.AddDays(30);
                context.Response.Cookies.Append("__Secure-CS-Refresh", cookie.Value!, options);
            }
        }

        if (response.Body is AuthResponses.ValidationProblemPayload validation)
            return Results.ValidationProblem(validation.Errors);
        if (response.StatusCode == StatusCodes.Status503ServiceUnavailable && response.Body is { } problem)
        {
            var detail = problem.GetType().GetProperty("title")?.GetValue(problem)?.ToString() ?? "Authentication is temporarily unavailable.";
            return Results.Problem(detail, statusCode: response.StatusCode);
        }
        if (response.Body is null) return Results.StatusCode(response.StatusCode);
        return Results.Json(response.Body, statusCode: response.StatusCode);
    }
}
