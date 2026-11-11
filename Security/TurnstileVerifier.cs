using System.Net.Http.Json;
using System.Text.Json.Serialization;

namespace CompareShopAuthAPI.Security;

public sealed record CaptchaResult(bool Accepted, string? FailureCode = null);

public sealed class TurnstileVerifier(IHttpClientFactory clients, IConfiguration configuration, IWebHostEnvironment environment, ILogger<TurnstileVerifier> logger)
{
    private const string VerifyEndpoint = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

    public async Task<CaptchaResult> VerifyAsync(string? token, string? remoteIp, CancellationToken cancellationToken)
    {
        if (!configuration.GetValue("Turnstile:Enabled", false)) return new CaptchaResult(true);
        if (string.IsNullOrWhiteSpace(token)) return new CaptchaResult(false, "captcha_failed");
        var secret = configuration["Turnstile:Secret"];
        if (string.IsNullOrWhiteSpace(secret))
        {
            logger.LogError("Turnstile is enabled but its secret is unavailable.");
            return new CaptchaResult(false, "captcha_failed");
        }
        TurnstileResponse? response;
        try
        {
            using var form = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["secret"] = secret,
                ["response"] = token,
                ["remoteip"] = remoteIp ?? ""
            });
            using var result = await clients.CreateClient(nameof(TurnstileVerifier)).PostAsync(VerifyEndpoint, form, cancellationToken);
            if (!result.IsSuccessStatusCode) throw new HttpRequestException("Turnstile siteverify returned a non-success status.");
            response = await result.Content.ReadFromJsonAsync<TurnstileResponse>(cancellationToken: cancellationToken);
        }
        catch (Exception ex) when (ex is HttpRequestException || ex is TaskCanceledException && !cancellationToken.IsCancellationRequested)
        {
            if (environment.IsDevelopment() && configuration.GetValue("Turnstile:AllowUnavailableInDev", false))
            {
                logger.LogWarning("Turnstile transport unavailable; explicit development-only bypass applied.");
                return new CaptchaResult(true);
            }
            logger.LogWarning("Turnstile siteverify transport failed ({ExceptionType}).", ex.GetType().Name);
            return new CaptchaResult(false, "captcha_failed");
        }
        catch (System.Text.Json.JsonException)
        {
            return new CaptchaResult(false, "captcha_failed");
        }
        if (response?.Success != true || string.IsNullOrWhiteSpace(response.Hostname)) return new CaptchaResult(false, "captcha_failed");
        var allowed = (configuration.GetSection("Turnstile:AllowedHostnames").Get<string[]>() ?? [])
            .Where(host => !(!environment.IsDevelopment() && string.Equals(host, "example.com", StringComparison.OrdinalIgnoreCase)));
        return allowed.Contains(response.Hostname, StringComparer.OrdinalIgnoreCase)
            ? new CaptchaResult(true)
            : new CaptchaResult(false, "captcha_failed");
    }

    private sealed class TurnstileResponse
    {
        [JsonPropertyName("success")] public bool Success { get; init; }
        [JsonPropertyName("hostname")] public string? Hostname { get; init; }
    }
}
