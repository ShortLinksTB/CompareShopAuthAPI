using CompareShopAuthAPI.Security;
using Microsoft.AspNetCore.Identity;

namespace CompareShopAuthAPI.Application;

public interface IAuthIdentityPort
{
    string? NormalizeEmail(string? email);
    Task<AuthUser?> FindByEmailAsync(string email);
    Task<AuthUser?> FindByIdAsync(string userId);
    Task<IdentityResult> CreateAsync(AuthUser user, string password);
    Task<SignInResult> CheckPasswordSignInAsync(AuthUser user, string password, bool lockoutOnFailure);
    Task<IdentityResult> ChangePasswordAsync(AuthUser user, string currentPassword, string newPassword);
    Task<IdentityResult> RemovePasswordAsync(AuthUser user);
    Task<IdentityResult> AddPasswordAsync(AuthUser user, string newPassword);
}

public sealed class AuthIdentityAdapter(UserManager<AuthUser> users, SignInManager<AuthUser> signIn) : IAuthIdentityPort
{
    public string? NormalizeEmail(string? email) => users.NormalizeEmail(email);
    public Task<AuthUser?> FindByEmailAsync(string email) => users.FindByEmailAsync(email);
    public Task<AuthUser?> FindByIdAsync(string userId) => users.FindByIdAsync(userId);
    public Task<IdentityResult> CreateAsync(AuthUser user, string password) => users.CreateAsync(user, password);
    public Task<SignInResult> CheckPasswordSignInAsync(AuthUser user, string password, bool lockoutOnFailure) => signIn.CheckPasswordSignInAsync(user, password, lockoutOnFailure);
    public Task<IdentityResult> ChangePasswordAsync(AuthUser user, string currentPassword, string newPassword) => users.ChangePasswordAsync(user, currentPassword, newPassword);
    public Task<IdentityResult> RemovePasswordAsync(AuthUser user) => users.RemovePasswordAsync(user);
    public Task<IdentityResult> AddPasswordAsync(AuthUser user, string newPassword) => users.AddPasswordAsync(user, newPassword);
}

public interface IAuthRateLimitPort
{
    Task<bool> TryConsumeAsync(string scope, string subject, int limit, TimeSpan window, CancellationToken cancellationToken);
}

public interface IAuthEmailOutboxPort
{
    void Enqueue(string recipient, string template, Dictionary<string, string> data);
}

public interface ICaptchaVerificationPort
{
    Task<CaptchaResult> VerifyAsync(string? token, string? remoteIp, CancellationToken cancellationToken);
}
