using CompareShopAuthAPI.Application;
using Xunit;

namespace CompareShopAuthAPI.Tests;

public sealed class PasswordPolicyTests
{
    private readonly PasswordPolicy _policy = new();

    [Theory]
    [InlineData("short", "person@example.com")]
    [InlineData("This password phrase keeps going far beyond any reasonable password size and repeats a lot of unnecessary words so that the total length is definitely above one hundred and twenty eight characters which should be rejected by the password policy.", "person@example.com")]
    public void RejectsPasswordsOutsideLengthRange(string password, string email)
        => Assert.Contains("password", _policy.Validate(email, password).Keys);

    [Theory]
    [InlineData("password", "person@example.com")]
    [InlineData("PASSWORD", "person@example.com")]
    public void RejectsCommonPasswords(string password, string email)
        => Assert.Contains("password", _policy.Validate(email, password).Keys);

    [Fact]
    public void RejectsPasswordContainingEmailLocalPartIgnoringCase()
        => Assert.Contains("password", _policy.Validate("Andy@example.com", "safeAndyPassword42").Keys);

    [Fact]
    public void AcceptsValidPassword()
        => Assert.Empty(_policy.Validate("andy@example.com", "S0mething-long-and-unique"));
}
