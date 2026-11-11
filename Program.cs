using System.Security.Cryptography;
using System.Text;
using CompareShopAuthAPI;
using CompareShopAuthAPI.Data;
using CompareShopAuthAPI.Security;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddDbContext<AuthDbContext>(o => o.UseSqlServer(builder.Configuration.GetConnectionString("Auth")));
builder.Services.AddIdentityCore<AuthUser>(o =>
{
    o.Password.RequireDigit = false;
    o.Password.RequireLowercase = false;
    o.Password.RequireUppercase = false;
    o.Password.RequireNonAlphanumeric = false;
    o.Password.RequiredLength = 8;
    o.Password.RequiredUniqueChars = 1;
    o.Lockout.MaxFailedAccessAttempts = TestLimit(builder.Configuration, builder.Environment.IsEnvironment("Testing"), "Lockout:MaxFailedAccessAttempts", 5);
    o.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
    o.User.RequireUniqueEmail = true;
}).AddEntityFrameworkStores<AuthDbContext>().AddSignInManager();
builder.Services.AddScoped<IPasswordHasher<AuthUser>, Pbkdf2Sha256PasswordHasher>();
builder.Services.AddSingleton<PasswordPolicy>();
builder.Services.AddSingleton<UnknownUserCredential>();
builder.Services.AddSingleton<TimeProvider>(TimeProvider.System);
builder.Services.AddSingleton<AccessTokenIssuer>();
builder.Services.AddSingleton<SecretPayloadProtector>();
builder.Services.AddScoped<AuthEmailOutbox>();
builder.Services.AddScoped<EmailOutboxBatchDispatcher>();
builder.Services.AddSingleton<IEmailMessagePublisher, RabbitMqEmailMessagePublisher>();
builder.Services.AddScoped<DistributedThrottle>();
builder.Services.AddHostedService<EmailOutboxPublisher>();
builder.Services.AddHostedService<ThrottleBucketRetentionService>();
builder.Services.AddHttpClient(nameof(TurnstileVerifier), client => client.Timeout = TimeSpan.FromSeconds(5));
builder.Services.AddScoped<TurnstileVerifier>();
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer();
builder.Services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme).Configure<AccessTokenIssuer>((o, issuer) =>
{
    o.TokenValidationParameters = issuer.ValidationParameters();
    o.MapInboundClaims = false;
    o.Events = new JwtBearerEvents { OnTokenValidated = context =>
    {
        if (context.Principal?.FindFirst("email_verified")?.Value != "true") context.Fail("Email verification is required.");
        return Task.CompletedTask;
    } };
});
builder.Services.AddAuthorization();
var uiOrigin = builder.Configuration["Cors:UiOrigin"];
builder.Services.AddCors(o => o.AddDefaultPolicy(p => { if (!string.IsNullOrWhiteSpace(uiOrigin)) p.WithOrigins(uiOrigin).AllowAnyHeader().AllowAnyMethod().AllowCredentials(); }));
builder.Services.AddHealthChecks();
var app = builder.Build();
app.UseMiddleware<ResponseTimingMiddleware>();
app.UseCors();
app.UseAuthentication();
app.UseAuthorization();

app.MapHealthChecks("/health");
app.MapGet("/ready", async (AuthDbContext db, CancellationToken ct) =>
    await db.Database.CanConnectAsync(ct) ? Results.Ok(new { status = "ready" }) : Results.StatusCode(503));
var auth = app.MapGroup("/api/v1/auth");

auth.MapPost("/register", async (HttpContext http, RegisterRequest request, UserManager<AuthUser> users, AuthDbContext db, AuthEmailOutbox outbox, DistributedThrottle throttle, PasswordPolicy policy, TurnstileVerifier captcha, TimeProvider clock, IConfiguration config, CancellationToken ct) =>
{
    var captchaResult = await captcha.VerifyAsync(request.CaptchaToken, http.Connection.RemoteIpAddress?.ToString(), ct);
    if (!captchaResult.Accepted) return Results.BadRequest(new { code = "captcha_failed" });
    if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrEmpty(request.Password))
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["request"] = ["Email and password are required."] });
    var email = request.Email.Trim();
    var ip = http.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    if (!await throttle.TryConsumeAsync("register:ip", ip, TestLimit(config, builder.Environment.IsEnvironment("Testing"), "Throttle:RegisterIpPerHour", 10), TimeSpan.FromHours(1), ct) ||
        !await throttle.TryConsumeAsync("register:email", email, TestLimit(config, builder.Environment.IsEnvironment("Testing"), "Throttle:RegisterEmailPerHour", 5), TimeSpan.FromHours(1), ct)) return Results.StatusCode(429);
    var errors = policy.Validate(email, request.Password);
    if (errors.Count != 0) return Results.ValidationProblem(errors);
    var user = new AuthUser { UserName = email, Email = email, EmailConfirmed = false };
    await using var transaction = await db.Database.BeginTransactionAsync(System.Data.IsolationLevel.Serializable, ct);
    var result = await users.CreateAsync(user, request.Password);
    if (!result.Succeeded)
    {
        await transaction.RollbackAsync(ct);
        if (result.Errors.Any(e => e.Code == "DuplicateUserName" || e.Code == "DuplicateEmail"))
        {
            outbox.Enqueue(email, "auth-existing-account", new Dictionary<string, string> { ["displayName"] = "" });
            await db.SaveChangesAsync(ct);
            return Results.Accepted(value: GenericEmailResponse());
        }
        return Results.ValidationProblem(result.Errors.GroupBy(e => e.Code).ToDictionary(g => g.Key, g => g.Select(e => e.Description).ToArray()));
    }
    var rawToken = CreateSecret();
    db.EmailVerifications.Add(new EmailVerification { Id = Guid.NewGuid(), UserId = user.Id, TokenHash = Hash(rawToken), ExpiresAt = clock.GetUtcNow().AddHours(24) });
    var link = $"{config["CompareShopUI:BaseUrl"]?.TrimEnd('/')}/verify-email?email={Uri.EscapeDataString(email)}&token={Uri.EscapeDataString(rawToken)}";
    outbox.Enqueue(email, "auth-verify", new Dictionary<string, string> { ["verificationLink"] = link });
    db.AuthEvents.Add(NewEvent(user.Id, "registered", http));
    await db.SaveChangesAsync(ct);
    await transaction.CommitAsync(ct);
    return Results.Accepted(value: GenericEmailResponse());
});

auth.MapPost("/login", async (HttpContext http, LoginRequest request, UserManager<AuthUser> users, SignInManager<AuthUser> signIn, UnknownUserCredential unknownUser, AuthDbContext db, DistributedThrottle throttle, AccessTokenIssuer issuer, TurnstileVerifier captcha, TimeProvider clock, IConfiguration config, CancellationToken ct) =>
{
    var captchaResult = await captcha.VerifyAsync(request.CaptchaToken, http.Connection.RemoteIpAddress?.ToString(), ct);
    if (!captchaResult.Accepted) return Results.BadRequest(new { code = "captcha_failed" });
    var emailKey = request.Email?.Trim() ?? "";
    var password = request.Password ?? "";
    var ipKey = http.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    if (!await throttle.TryConsumeAsync("login:ip", ipKey, TestLimit(config, builder.Environment.IsEnvironment("Testing"), "Throttle:LoginIpPer15Minutes", 10), TimeSpan.FromMinutes(15), ct) ||
        !await throttle.TryConsumeAsync("login:email", emailKey, TestLimit(config, builder.Environment.IsEnvironment("Testing"), "Throttle:LoginEmailPer15Minutes", 5), TimeSpan.FromMinutes(15), ct)) return Results.StatusCode(429);
    var normalized = users.NormalizeEmail(emailKey);
    var user = normalized is null ? null : await users.FindByEmailAsync(emailKey);
    if (user is null) unknownUser.Verify(password);
    var signInResult = user is null ? null : await signIn.CheckPasswordSignInAsync(user, password, lockoutOnFailure: true);
    if (signInResult?.IsLockedOut == true) unknownUser.Verify(password);
    if (signInResult?.Succeeded == true && user is not null && !user.EmailConfirmed)
    {
        db.AuthEvents.Add(NewEvent(user?.Id, "login_failed", http));
        await db.SaveChangesAsync(ct);
        return Results.Json(new { code = "email_not_verified" }, statusCode: StatusCodes.Status403Forbidden);
    }
    if (signInResult?.Succeeded != true || user is null)
    {
        db.AuthEvents.Add(NewEvent(user?.Id, "login_failed", http));
        await db.SaveChangesAsync(ct);
        return Results.Json(new { code = "invalid_credentials" }, statusCode: StatusCodes.Status401Unauthorized);
    }
    db.AuthEvents.Add(NewEvent(user.Id, "login_succeeded", http));
    await db.SaveChangesAsync(ct);
    if (!issuer.IsConfigured) return Results.Problem("Authentication is temporarily unavailable.", statusCode: StatusCodes.Status503ServiceUnavailable);
    var refresh = CreateSecret();
    var now = clock.GetUtcNow();
    db.RefreshSessions.Add(new RefreshSession { Id = Guid.NewGuid(), FamilyId = Guid.NewGuid(), UserId = user.Id, TokenHash = Hash(refresh), CreatedAt = now, ExpiresAt = now.AddDays(30), FamilyExpiresAt = now.AddDays(90) });
    await db.SaveChangesAsync(ct);
    SetRefreshCookie(http, refresh);
    return Results.Ok(new { accessToken = issuer.Issue(user, clock.GetUtcNow()), tokenType = "Bearer", expiresIn = 900 });
});

auth.MapPost("/verify-email", async (HttpContext http, VerificationRequest request, UserManager<AuthUser> users, AuthDbContext db, TimeProvider clock, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.Token)) return Results.BadRequest(new { code = "verification_invalid" });
    var email = request.Email.Trim();
    var tokenHash = Hash(request.Token);
    await using var transaction = await db.Database.BeginTransactionAsync(System.Data.IsolationLevel.Serializable, ct);
    var verification = await db.EmailVerifications.FromSqlInterpolated($"SELECT * FROM [EmailVerifications] WITH (UPDLOCK, HOLDLOCK) WHERE [TokenHash] = {tokenHash}").SingleOrDefaultAsync(ct);
    if (verification is null || verification.ExpiresAt <= clock.GetUtcNow() || verification.UsedAt is not null)
    {
        await transaction.RollbackAsync(ct);
        return Results.BadRequest(new { code = "verification_invalid" });
    }
    var user = await users.FindByIdAsync(verification.UserId);
    if (user is null || !string.Equals(user.Email, email, StringComparison.OrdinalIgnoreCase))
    {
        await transaction.RollbackAsync(ct);
        return Results.BadRequest(new { code = "verification_invalid" });
    }
    user.EmailConfirmed = true;
    verification.UsedAt = clock.GetUtcNow();
    db.AuthEvents.Add(NewEvent(user.Id, "email_verified", http));
    await db.SaveChangesAsync(ct);
    await transaction.CommitAsync(ct);
    return Results.Ok(new { message = "Email verified." });
});
auth.MapPost("/resend-verification", async (HttpContext http, EmailRequest request, UserManager<AuthUser> users, AuthDbContext db, AuthEmailOutbox outbox, DistributedThrottle throttle, TurnstileVerifier captcha, TimeProvider clock, IConfiguration config, CancellationToken ct) =>
{
    var captchaResult = await captcha.VerifyAsync(request.CaptchaToken, http.Connection.RemoteIpAddress?.ToString(), ct);
    if (!captchaResult.Accepted) return Results.BadRequest(new { code = "captcha_failed" });
    var generic = GenericEmailResponse();
    var ip = http.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    var requestedEmail = request.Email?.Trim() ?? "";
    var allowed = await throttle.TryConsumeAsync("resend:ip", ip, TestLimit(config, builder.Environment.IsEnvironment("Testing"), "Throttle:ResendIpPerHour", 10), TimeSpan.FromHours(1), ct) &&
        await throttle.TryConsumeAsync("resend:email", requestedEmail, TestLimit(config, builder.Environment.IsEnvironment("Testing"), "Throttle:ResendEmailPerHour", 3), TimeSpan.FromHours(1), ct);
    if (!allowed) return Results.Accepted(value: generic);
    var user = await users.FindByEmailAsync(requestedEmail);
    if (user is null || user.EmailConfirmed) return Results.Accepted(value: generic);
    await using var transaction = await db.Database.BeginTransactionAsync(System.Data.IsolationLevel.Serializable, ct);
    var now = clock.GetUtcNow();
    await db.EmailVerifications.Where(v => v.UserId == user.Id && v.UsedAt == null).ExecuteUpdateAsync(set => set.SetProperty(v => v.UsedAt, now), ct);
    var token = CreateSecret();
    db.EmailVerifications.Add(new EmailVerification { Id = Guid.NewGuid(), UserId = user.Id, TokenHash = Hash(token), ExpiresAt = now.AddHours(24) });
    var link = $"{config["CompareShopUI:BaseUrl"]?.TrimEnd('/')}/verify-email?email={Uri.EscapeDataString(user.Email!)}&token={Uri.EscapeDataString(token)}";
    outbox.Enqueue(user.Email!, "auth-verify", new Dictionary<string, string> { ["verificationLink"] = link });
    db.AuthEvents.Add(NewEvent(user.Id, "verification_resent", http));
    await db.SaveChangesAsync(ct);
    await transaction.CommitAsync(ct);
    return Results.Accepted(value: generic);
});
auth.MapPost("/forgot-password", async (HttpContext http, EmailRequest request, UserManager<AuthUser> users, AuthDbContext db, AuthEmailOutbox outbox, DistributedThrottle throttle, TurnstileVerifier captcha, IConfiguration config, TimeProvider clock, CancellationToken ct) =>
{
    var captchaResult = await captcha.VerifyAsync(request.CaptchaToken, http.Connection.RemoteIpAddress?.ToString(), ct);
    if (!captchaResult.Accepted) return Results.BadRequest(new { code = "captcha_failed" });
    var generic = GenericEmailResponse();
    var ip = http.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    var requestedEmail = request.Email?.Trim() ?? "";
    var allowed = await throttle.TryConsumeAsync("forgot:ip", ip, TestLimit(config, builder.Environment.IsEnvironment("Testing"), "Throttle:ForgotIpPerHour", 3), TimeSpan.FromHours(1), ct) &&
        await throttle.TryConsumeAsync("forgot:email", requestedEmail, TestLimit(config, builder.Environment.IsEnvironment("Testing"), "Throttle:ForgotEmailPerHour", 3), TimeSpan.FromHours(1), ct);
    if (!allowed) return Results.Accepted(value: generic);
    var user = await users.FindByEmailAsync(requestedEmail);
    if (user is null || !user.EmailConfirmed) return Results.Accepted(value: generic);
    var now = clock.GetUtcNow();
    await using var transaction = await db.Database.BeginTransactionAsync(System.Data.IsolationLevel.Serializable, ct);
    await db.PasswordResetPins.Where(p => p.UserId == user.Id && p.UsedAt == null).ExecuteUpdateAsync(set => set.SetProperty(p => p.UsedAt, now), ct);
    var pin = RandomNumberGenerator.GetInt32(0, 1_000_000).ToString("D6");
    var salt = CreateSecret();
    db.PasswordResetPins.Add(new PasswordResetPin { Id = Guid.NewGuid(), UserId = user.Id, NormalizedEmail = users.NormalizeEmail(user.Email)!, PinSalt = salt, PinHash = PinHash(config, user.Id, salt, pin), CreatedAt = now, ExpiresAt = now.AddMinutes(10) });
    var digits = pin.ToCharArray();
    var pinData = new Dictionary<string, string> { ["displayName"] = "", ["expiresInMinutes"] = "10", ["pinSpaced"] = string.Join(' ', digits), ["pinGrouped"] = pin[..3] + "-" + pin[3..] };
    outbox.Enqueue(user.Email!, "auth-reset-password-pin", pinData);
    db.AuthEvents.Add(NewEvent(user.Id, "password_reset_requested", http));
    await db.SaveChangesAsync(ct);
    await transaction.CommitAsync(ct);
    return Results.Accepted(value: generic);
});
auth.MapPost("/verify-reset-code", async (VerifyResetCodeRequest request, UserManager<AuthUser> users, AuthDbContext db, IConfiguration config, TimeProvider clock, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.Code)) return Results.BadRequest(new { code = "reset_code_invalid" });
    var email = request.Email.Trim();
    var user = await users.FindByEmailAsync(email);
    if (user is null) return Results.BadRequest(new { code = "reset_code_invalid" });
    var normalized = users.NormalizeEmail(email);
    await using var transaction = await db.Database.BeginTransactionAsync(System.Data.IsolationLevel.Serializable, ct);
    var pin = await db.PasswordResetPins.FromSqlInterpolated($"SELECT TOP (1) * FROM [PasswordResetPins] WITH (UPDLOCK, HOLDLOCK) WHERE [NormalizedEmail] = {normalized} AND [UsedAt] IS NULL ORDER BY [CreatedAt] DESC").SingleOrDefaultAsync(ct);
    var now = clock.GetUtcNow();
    if (pin is null || pin.ExpiresAt <= now || pin.FailedAttempts >= 5)
    {
        await transaction.RollbackAsync(ct);
        return Results.BadRequest(new { code = "reset_code_invalid" });
    }
    if (!CryptographicOperations.FixedTimeEquals(Convert.FromHexString(pin.PinHash), Convert.FromHexString(PinHash(config, user.Id, pin.PinSalt, request.Code))))
    {
        pin.FailedAttempts++;
        if (pin.FailedAttempts >= 5) pin.UsedAt = now;
        await db.SaveChangesAsync(ct);
        await transaction.CommitAsync(ct);
        return Results.BadRequest(new { code = "reset_code_invalid" });
    }
    var resetToken = CreateSecret();
    pin.UsedAt = now;
    db.PasswordResetGrants.Add(new PasswordResetGrant { Id = Guid.NewGuid(), UserId = user.Id, TokenHash = Hash(resetToken), ExpiresAt = now.AddMinutes(5) });
    await db.SaveChangesAsync(ct);
    await transaction.CommitAsync(ct);
    return Results.Ok(new { resetToken, expiresIn = 300 });
});
auth.MapPost("/reset-password", async (HttpContext http, ResetPasswordRequest request, UserManager<AuthUser> users, AuthDbContext db, PasswordPolicy policy, TimeProvider clock, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(request.ResetToken) || string.IsNullOrEmpty(request.NewPassword)) return Results.BadRequest(new { code = "reset_token_invalid" });
    var grantHash = Hash(request.ResetToken);
    await using var transaction = await db.Database.BeginTransactionAsync(System.Data.IsolationLevel.Serializable, ct);
    var grant = await db.PasswordResetGrants.FromSqlInterpolated($"SELECT * FROM [PasswordResetGrants] WITH (UPDLOCK, HOLDLOCK) WHERE [TokenHash] = {grantHash}").SingleOrDefaultAsync(ct);
    if (grant is null || grant.UsedAt is not null || grant.ExpiresAt <= clock.GetUtcNow())
    {
        await transaction.RollbackAsync(ct);
        return Results.BadRequest(new { code = "reset_token_invalid" });
    }
    var user = await users.FindByIdAsync(grant.UserId);
    if (user?.Email is null) { await transaction.RollbackAsync(ct); return Results.BadRequest(new { code = "reset_token_invalid" }); }
    var errors = policy.Validate(user.Email, request.NewPassword);
    if (errors.Count != 0) { await transaction.RollbackAsync(ct); return Results.ValidationProblem(errors); }
    var removed = await users.RemovePasswordAsync(user);
    var changed = removed.Succeeded ? await users.AddPasswordAsync(user, request.NewPassword) : removed;
    if (!changed.Succeeded)
    {
        await transaction.RollbackAsync(ct);
        return Results.ValidationProblem(changed.Errors.GroupBy(e => e.Code).ToDictionary(g => g.Key, g => g.Select(e => e.Description).ToArray()));
    }
    grant.UsedAt = clock.GetUtcNow();
    await db.RefreshSessions.Where(s => s.UserId == user.Id && s.RevokedAt == null).ExecuteUpdateAsync(set => set.SetProperty(s => s.RevokedAt, clock.GetUtcNow()), ct);
    db.AuthEvents.Add(NewEvent(user.Id, "password_reset_completed", http));
    await db.SaveChangesAsync(ct);
    await transaction.CommitAsync(ct);
    return Results.Ok(new { message = "Password updated." });
});
auth.MapPost("/change-password", async (HttpContext http, ChangePasswordRequest request, UserManager<AuthUser> users, AuthDbContext db, AuthEmailOutbox outbox, PasswordPolicy policy, TimeProvider clock, CancellationToken ct) =>
{
    if (string.IsNullOrEmpty(request.CurrentPassword) || string.IsNullOrEmpty(request.NewPassword)) return Results.BadRequest(new { code = "password_change_failed" });
    var userId = http.User.FindFirst("sub")?.Value;
    if (string.IsNullOrWhiteSpace(userId)) return Results.Unauthorized();
    var user = await users.FindByIdAsync(userId);
    if (user?.Email is null) return Results.Unauthorized();
    var errors = policy.Validate(user.Email, request.NewPassword);
    if (errors.Count != 0) return Results.ValidationProblem(errors);
    await using var transaction = await db.Database.BeginTransactionAsync(ct);
    var result = await users.ChangePasswordAsync(user, request.CurrentPassword, request.NewPassword);
    if (!result.Succeeded)
    {
        await transaction.RollbackAsync(ct);
        return Results.BadRequest(new { code = "password_change_failed" });
    }
    await db.RefreshSessions.Where(s => s.UserId == user.Id && s.RevokedAt == null).ExecuteUpdateAsync(set => set.SetProperty(s => s.RevokedAt, clock.GetUtcNow()), ct);
    outbox.Enqueue(user.Email, "auth-password-changed", new Dictionary<string, string> { ["displayName"] = "" });
    db.AuthEvents.Add(NewEvent(user.Id, "password_changed", http));
    await db.SaveChangesAsync(ct);
    await transaction.CommitAsync(ct);
    return Results.Ok(new { message = "Password updated." });
}).RequireAuthorization();
auth.MapGet("/me", (System.Security.Claims.ClaimsPrincipal principal) => Results.Ok(new { id = principal.FindFirst("sub")?.Value, email = principal.FindFirst("email")?.Value })).RequireAuthorization();
auth.MapPost("/refresh", async (HttpContext http, AuthDbContext db, UserManager<AuthUser> users, AccessTokenIssuer issuer, TimeProvider clock, IConfiguration config, CancellationToken ct) =>
{
    if (!IsTrustedMutation(http, config)) return Results.StatusCode(403);
    var raw = http.Request.Cookies["__Secure-CS-Refresh"];
    if (string.IsNullOrEmpty(raw)) return Results.Unauthorized();
    var hash = Hash(raw);
    await using var rotation = await db.Database.BeginTransactionAsync(System.Data.IsolationLevel.Serializable, ct);
    var session = await db.RefreshSessions.FromSqlInterpolated($"SELECT * FROM [RefreshSessions] WITH (UPDLOCK, HOLDLOCK) WHERE [TokenHash] = {hash}").SingleOrDefaultAsync(ct);
    if (session is null) return Results.Unauthorized();
    var now = clock.GetUtcNow();
    if (session.RevokedAt is not null)
    {
        await db.RefreshSessions.Where(s => s.FamilyId == session.FamilyId && s.RevokedAt == null).ExecuteUpdateAsync(set => set.SetProperty(s => s.RevokedAt, now), ct);
        await rotation.CommitAsync(ct);
        ClearRefreshCookie(http);
        return Results.Unauthorized();
    }
    if (session.ExpiresAt <= now || session.FamilyExpiresAt <= now) { session.RevokedAt = now; await db.SaveChangesAsync(ct); await rotation.CommitAsync(ct); ClearRefreshCookie(http); return Results.Unauthorized(); }
    if (!issuer.IsConfigured) return Results.Problem("Authentication is temporarily unavailable.", statusCode: 503);
    var replacement = CreateSecret();
    var replacementHash = Hash(replacement);
    session.RevokedAt = now;
    session.ReplacedByHash = replacementHash;
    db.RefreshSessions.Add(new RefreshSession { Id = Guid.NewGuid(), FamilyId = session.FamilyId, UserId = session.UserId, TokenHash = replacementHash, CreatedAt = now, ExpiresAt = Min(now.AddDays(30), session.FamilyExpiresAt), FamilyExpiresAt = session.FamilyExpiresAt });
    await db.SaveChangesAsync(ct);
    var user = await users.FindByIdAsync(session.UserId);
    if (user is null) { await rotation.RollbackAsync(ct); ClearRefreshCookie(http); return Results.Unauthorized(); }
    await rotation.CommitAsync(ct);
    SetRefreshCookie(http, replacement);
    return Results.Ok(new { accessToken = issuer.Issue(user, now), tokenType = "Bearer", expiresIn = 900 });
});
auth.MapPost("/logout", async (HttpContext http, AuthDbContext db, TimeProvider clock, IConfiguration config, CancellationToken ct) =>
{
    if (!IsTrustedMutation(http, config)) return Results.StatusCode(403);
    var raw = http.Request.Cookies["__Secure-CS-Refresh"];
    if (!string.IsNullOrEmpty(raw))
    {
        var hash = Hash(raw);
        await db.RefreshSessions.Where(s => s.TokenHash == hash && s.RevokedAt == null).ExecuteUpdateAsync(set => set.SetProperty(s => s.RevokedAt, clock.GetUtcNow()), ct);
    }
    ClearRefreshCookie(http);
    return Results.NoContent();
});
app.MapGet("/.well-known/jwks.json", (AccessTokenIssuer issuer) => Results.Json(issuer.Jwks()));
auth.MapGet("/jwks", (AccessTokenIssuer issuer) => Results.Json(issuer.Jwks()));

app.Run();

static string CreateSecret() => Microsoft.AspNetCore.WebUtilities.WebEncoders.Base64UrlEncode(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
static int TestLimit(IConfiguration config, bool isTest, string key, int productionValue) => isTest ? config.GetValue(key, productionValue) : productionValue;
static string Hash(string raw) => Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(raw)));
static string PinHash(IConfiguration config, string userId, string salt, string pin)
{
    var pepper = config["Pin:Pepper"];
    if (string.IsNullOrWhiteSpace(pepper)) throw new InvalidOperationException("PIN hashing secret is not configured.");
    using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(pepper));
    return Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes($"{userId}:{salt}:{pin}")));
}

static AuthEvent NewEvent(string? userId, string type, HttpContext? http) => new() { UserId = userId, Type = type, OccurredAt = DateTimeOffset.UtcNow, IpAddress = http?.Connection.RemoteIpAddress?.ToString(), UserAgent = http?.Request.Headers.UserAgent.ToString() };
static object GenericEmailResponse() => new { message = "If an eligible account exists, instructions will be sent." };
static DateTimeOffset Min(DateTimeOffset first, DateTimeOffset second) => first <= second ? first : second;
static bool IsTrustedMutation(HttpContext http, IConfiguration configuration)
{
    var origin = configuration["Cors:UiOrigin"];
    return !string.IsNullOrWhiteSpace(origin) && http.Request.Headers.Origin == origin && http.Request.Headers["X-Requested-With"] == "XMLHttpRequest";
}
static void SetRefreshCookie(HttpContext http, string value) => http.Response.Cookies.Append("__Secure-CS-Refresh", value, new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Strict, Path = "/api/v1/auth", Expires = DateTimeOffset.UtcNow.AddDays(30), IsEssential = true });
static void ClearRefreshCookie(HttpContext http) => http.Response.Cookies.Delete("__Secure-CS-Refresh", new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Strict, Path = "/api/v1/auth" });

namespace CompareShopAuthAPI
{
    public sealed record RegisterRequest(string Email, string Password, string? CaptchaToken = null);
    public sealed record LoginRequest(string Email, string Password, string? CaptchaToken = null);
    public sealed record EmailRequest(string Email, string? CaptchaToken = null);
    public sealed record VerificationRequest(string Email, string Token);
    public sealed record VerifyResetCodeRequest(string Email, string Code);
    public sealed record ResetPasswordRequest(string ResetToken, string NewPassword);
    public sealed record ChangePasswordRequest(string CurrentPassword, string NewPassword);
    public sealed class AuthUser : IdentityUser { }
}

public partial class Program { }
