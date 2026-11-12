using CompareShopAuthAPI.Application;

namespace CompareShopAuthAPI.Infrastructure;

public sealed class ConfigurationAuthSettings(IConfiguration configuration, IHostEnvironment environment) : IAuthSettings
{
    public string? Get(string key) => configuration[key];
    public bool GetBoolean(string key, bool defaultValue = false) => configuration.GetValue(key, defaultValue);
    public bool IsDevelopment => environment.IsDevelopment();
    public int GetLimit(string key, int productionValue) =>
        environment.IsEnvironment("Testing") ? configuration.GetValue(key, productionValue) : productionValue;
}
