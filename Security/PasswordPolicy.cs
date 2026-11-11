namespace CompareShopAuthAPI.Security;

public sealed class PasswordPolicy
{
    public const string DenylistVersion = "2026-11-11";

    private static readonly HashSet<string> CommonPasswords = new(StringComparer.Ordinal)
    {
        "password", "password1", "password123", "12345678", "123456789", "1234567890",
        "qwerty", "qwerty123", "qwertyuiop", "letmein", "letmein123", "welcome", "welcome1",
        "admin123", "admin1234", "iloveyou", "abc12345", "monkey123", "dragon123", "football1",
        "sunshine1", "princess1", "trustno1", "changeme", "passw0rd", "P@ssw0rd".ToLowerInvariant()
    };

    public Dictionary<string, string[]> Validate(string email, string password)
    {
        var errors = new Dictionary<string, string[]>();
        if (password.Length is < 8 or > 128)
            errors["password"] = ["Password must be between 8 and 128 characters."];
        else
        {
            if (CommonPasswords.Contains(password.ToLowerInvariant()))
                errors["password"] = ["Choose a less common password."];
            var localPart = email.Split('@', 2)[0];
            if (localPart.Length > 0 && password.Contains(localPart, StringComparison.OrdinalIgnoreCase))
                errors["password"] = errors.GetValueOrDefault("password", []).Append("Password must not contain the email local part.").ToArray();
        }
        return errors;
    }
}
