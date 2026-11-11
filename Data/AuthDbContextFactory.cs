using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace CompareShopAuthAPI.Data;

public sealed class AuthDbContextFactory : IDesignTimeDbContextFactory<AuthDbContext>
{
    public AuthDbContext CreateDbContext(string[] args)
    {
        var connection = Environment.GetEnvironmentVariable("ConnectionStrings__Auth")
            ?? "Server=localhost;Database=CompareShopAuth;Integrated Security=True;TrustServerCertificate=True";
        var options = new DbContextOptionsBuilder<AuthDbContext>().UseSqlServer(connection).Options;
        return new AuthDbContext(options);
    }
}
