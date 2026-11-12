using CompareShopAuthAPI;
using CompareShopAuthAPI.Application;
using CompareShopAuthAPI.Data;
using CompareShopAuthAPI.Security;
using CompareShopAuthAPI.Http;
using CompareShopAuthAPI.Infrastructure;
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
builder.Services.AddSingleton<IAccessTokenPort>(services => services.GetRequiredService<AccessTokenIssuer>());
builder.Services.AddSingleton<SecretPayloadProtector>();
builder.Services.AddScoped<AuthEmailOutbox>();
builder.Services.AddScoped<IAuthEmailOutboxPort>(services => services.GetRequiredService<AuthEmailOutbox>());
builder.Services.AddScoped<DistributedThrottle>();
builder.Services.AddScoped<IAuthRateLimitPort>(services => services.GetRequiredService<DistributedThrottle>());
builder.Services.AddScoped<TurnstileVerifier>();
builder.Services.AddScoped<ICaptchaVerificationPort>(services => services.GetRequiredService<TurnstileVerifier>());
builder.Services.AddScoped<IAuthIdentityPort, AuthIdentityAdapter>();
builder.Services.AddScoped<IAuthDataPort, AuthDataAdapter>();
builder.Services.AddSingleton<IAuthSettings, ConfigurationAuthSettings>();
builder.Services.AddSingleton<IUnknownCredentialPort, UnknownUserCredential>();
builder.Services.AddScoped<IRegisterAccountUseCase, RegisterAccountUseCase>();
builder.Services.AddScoped<ILoginUseCase, LoginUseCase>();
builder.Services.AddScoped<IVerifyEmailUseCase, VerifyEmailUseCase>();
builder.Services.AddScoped<IResendVerificationUseCase, ResendVerificationUseCase>();
builder.Services.AddScoped<IPasswordRecoveryUseCase, PasswordRecoveryUseCase>();
builder.Services.AddScoped<IPasswordChangeUseCase, PasswordChangeUseCase>();
builder.Services.AddScoped<IRefreshSessionUseCase, RefreshSessionUseCase>();
builder.Services.AddScoped<EmailOutboxBatchDispatcher>();
builder.Services.AddSingleton<IEmailBrokerTransport, RabbitMqEmailBrokerTransport>();
builder.Services.AddSingleton<IEmailMessagePublisher, RabbitMqEmailMessagePublisher>();
builder.Services.AddHostedService<EmailOutboxPublisher>();
builder.Services.AddHostedService<ThrottleBucketRetentionService>();
builder.Services.AddHttpClient(nameof(TurnstileVerifier), client => client.Timeout = TimeSpan.FromSeconds(5));
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

auth.MapPost("/register", async (HttpContext http, RegisterRequest request, IRegisterAccountUseCase useCase, CancellationToken ct) => AuthEndpointAdapter.ToHttpResult(http, await useCase.ExecuteAsync(AuthEndpointAdapter.ReadContext(http), request, ct)));

auth.MapPost("/login", async (HttpContext http, LoginRequest request, ILoginUseCase useCase, CancellationToken ct) => AuthEndpointAdapter.ToHttpResult(http, await useCase.ExecuteAsync(AuthEndpointAdapter.ReadContext(http), request, ct)));

auth.MapPost("/verify-email", async (HttpContext http, VerificationRequest request, IVerifyEmailUseCase useCase, CancellationToken ct) => AuthEndpointAdapter.ToHttpResult(http, await useCase.ExecuteAsync(AuthEndpointAdapter.ReadContext(http), request, ct)));
auth.MapPost("/resend-verification", async (HttpContext http, EmailRequest request, IResendVerificationUseCase useCase, CancellationToken ct) => AuthEndpointAdapter.ToHttpResult(http, await useCase.ExecuteAsync(AuthEndpointAdapter.ReadContext(http), request, ct)));
auth.MapPost("/forgot-password", async (HttpContext http, EmailRequest request, IPasswordRecoveryUseCase useCase, CancellationToken ct) => AuthEndpointAdapter.ToHttpResult(http, await useCase.ForgotAsync(AuthEndpointAdapter.ReadContext(http), request, ct)));
auth.MapPost("/verify-reset-code", async (HttpContext http, VerifyResetCodeRequest request, IPasswordRecoveryUseCase useCase, CancellationToken ct) => AuthEndpointAdapter.ToHttpResult(http, await useCase.VerifyCodeAsync(request, ct)));
auth.MapPost("/reset-password", async (HttpContext http, ResetPasswordRequest request, IPasswordRecoveryUseCase useCase, CancellationToken ct) => AuthEndpointAdapter.ToHttpResult(http, await useCase.ResetAsync(AuthEndpointAdapter.ReadContext(http), request, ct)));
auth.MapPost("/change-password", async (HttpContext http, ChangePasswordRequest request, IPasswordChangeUseCase useCase, CancellationToken ct) => AuthEndpointAdapter.ToHttpResult(http, await useCase.ExecuteAsync(AuthEndpointAdapter.ReadContext(http), request, ct))).RequireAuthorization();
auth.MapGet("/me", (System.Security.Claims.ClaimsPrincipal principal) => Results.Ok(new { id = principal.FindFirst("sub")?.Value, email = principal.FindFirst("email")?.Value })).RequireAuthorization();
auth.MapPost("/refresh", async (HttpContext http, IRefreshSessionUseCase useCase, CancellationToken ct) => AuthEndpointAdapter.ToHttpResult(http, await useCase.RefreshAsync(AuthEndpointAdapter.ReadContext(http), ct)));
auth.MapPost("/logout", async (HttpContext http, IRefreshSessionUseCase useCase, CancellationToken ct) => AuthEndpointAdapter.ToHttpResult(http, await useCase.LogoutAsync(AuthEndpointAdapter.ReadContext(http), ct)));
app.MapGet("/.well-known/jwks.json", (AccessTokenIssuer issuer) => Results.Json(issuer.Jwks()));
auth.MapGet("/jwks", (AccessTokenIssuer issuer) => Results.Json(issuer.Jwks()));

app.Run();

static int TestLimit(IConfiguration config, bool isTest, string key, int productionValue) => isTest ? config.GetValue(key, productionValue) : productionValue;
namespace CompareShopAuthAPI
{
    public sealed class AuthUser : IdentityUser { }
}

public partial class Program { }
