
namespace CompareShopAuthAPI.Application;

public interface IRegisterAccountUseCase
{
    Task<AuthResponse> ExecuteAsync(AuthRequestContext context, RegisterRequest request, CancellationToken cancellationToken);
}

public sealed class RegisterAccountUseCase(
    IAuthIdentityPort users,
    IAuthDataPort data,
    IAuthEmailOutboxPort outbox,
    IAuthRateLimitPort throttle,
    PasswordPolicy policy,
    ICaptchaVerificationPort captcha,
    TimeProvider clock,
    IAuthSettings settings) : IRegisterAccountUseCase
{
    public async Task<AuthResponse> ExecuteAsync(AuthRequestContext context, RegisterRequest request, CancellationToken cancellationToken)
    {
        var captchaResult = await captcha.VerifyAsync(request.CaptchaToken, context.RemoteIp, cancellationToken);
        if (!captchaResult.Accepted) return AuthResponses.BadRequest(new { code = "captcha_failed" });
        if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrEmpty(request.Password))
            return AuthResponses.ValidationProblem(new Dictionary<string, string[]> { ["request"] = ["Email and password are required."] });

        var email = request.Email.Trim();
        var ip = context.RemoteIp ?? "unknown";
        if (!await throttle.TryConsumeAsync("register:ip", ip, settings.GetLimit("Throttle:RegisterIpPerHour", 10), TimeSpan.FromHours(1), cancellationToken) ||
            !await throttle.TryConsumeAsync("register:email", email, settings.GetLimit("Throttle:RegisterEmailPerHour", 5), TimeSpan.FromHours(1), cancellationToken))
            return AuthResponses.TooManyRequests();
        var errors = policy.Validate(email, request.Password);
        if (errors.Count != 0) return AuthResponses.ValidationProblem(errors);

        await using var transaction = await data.BeginTransactionAsync(cancellationToken);
        var result = await users.CreateAsync(email, request.Password, cancellationToken);
        if (!result.Succeeded)
        {
            await transaction.RollbackAsync(cancellationToken);
            if (result.Errors.Any(e => e.Code is "DuplicateUserName" or "DuplicateEmail"))
            {
                outbox.Enqueue(email, "auth-existing-account", new Dictionary<string, string> { ["displayName"] = "" });
                await data.SaveChangesAsync(cancellationToken);
                return AuthResponses.Accepted(AuthApplicationUtilities.GenericEmailResponse());
            }
            return AuthResponses.ValidationProblem(result.Errors.GroupBy(e => e.Code).ToDictionary(g => g.Key, g => g.Select(e => e.Description).ToArray()));
        }

        var user = await users.FindByEmailAsync(email);
        if (user is null) throw new InvalidOperationException("Identity did not return the newly created account.");
        var rawToken = AuthApplicationUtilities.CreateSecret();
        data.Add(new EmailVerification { Id = Guid.NewGuid(), UserId = user.Id, TokenHash = AuthApplicationUtilities.Hash(rawToken), ExpiresAt = clock.GetUtcNow().AddHours(24) });
        outbox.Enqueue(email, "auth-verify", AuthApplicationUtilities.VerificationTemplateData(rawToken));
        data.Add(AuthApplicationUtilities.NewEvent(user.Id, "registered", context, clock.GetUtcNow()));
        await data.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return AuthResponses.Accepted(AuthApplicationUtilities.GenericEmailResponse());
    }
}
