using CompareShopAuthAPI.Application;
using Microsoft.AspNetCore.Identity;

namespace CompareShopAuthAPI.Data;

public sealed class AuthIdentityAdapter(UserManager<AuthUser> users, SignInManager<AuthUser> signIn) : IAuthIdentityPort
{
    public string? NormalizeEmail(string? email) => users.NormalizeEmail(email);

    public async Task<AuthIdentityUser?> FindByEmailAsync(string email) => ToContract(await users.FindByEmailAsync(email));

    public async Task<AuthIdentityUser?> FindByIdAsync(string userId) => ToContract(await users.FindByIdAsync(userId));

    public async Task<AuthIdentityOperationResult> CreateAsync(string email, string password, CancellationToken cancellationToken)
    {
        var user = new AuthUser { UserName = email, Email = email, EmailConfirmed = false };
        return ToContract(await users.CreateAsync(user, password));
    }

    public async Task<AuthPasswordCheckResult> CheckPasswordAsync(string userId, string password, bool lockoutOnFailure)
    {
        var user = await users.FindByIdAsync(userId);
        if (user is null) return new(false, false);
        var result = await signIn.CheckPasswordSignInAsync(user, password, lockoutOnFailure);
        return new(result.Succeeded, result.IsLockedOut);
    }

    public async Task<AuthIdentityOperationResult> ConfirmEmailAsync(string userId)
    {
        var user = await users.FindByIdAsync(userId);
        if (user is null) return new(false, [new("UserNotFound", "The user was not found.")]);
        user.EmailConfirmed = true;
        return ToContract(await users.UpdateAsync(user));
    }

    public async Task<AuthIdentityOperationResult> ChangePasswordAsync(string userId, string currentPassword, string newPassword)
    {
        var user = await users.FindByIdAsync(userId);
        return user is null ? new(false, [new("UserNotFound", "The user was not found.")]) : ToContract(await users.ChangePasswordAsync(user, currentPassword, newPassword));
    }

    public async Task<AuthIdentityOperationResult> RemovePasswordAsync(string userId)
    {
        var user = await users.FindByIdAsync(userId);
        return user is null ? new(false, [new("UserNotFound", "The user was not found.")]) : ToContract(await users.RemovePasswordAsync(user));
    }

    public async Task<AuthIdentityOperationResult> AddPasswordAsync(string userId, string newPassword)
    {
        var user = await users.FindByIdAsync(userId);
        return user is null ? new(false, [new("UserNotFound", "The user was not found.")]) : ToContract(await users.AddPasswordAsync(user, newPassword));
    }

    private static AuthIdentityUser? ToContract(AuthUser? user) =>
        user is null ? null : new(user.Id, user.Email, user.EmailConfirmed);

    private static AuthIdentityOperationResult ToContract(IdentityResult result) =>
        new(result.Succeeded, result.Errors.Select(error => new AuthIdentityError(error.Code, error.Description)).ToArray());
}
