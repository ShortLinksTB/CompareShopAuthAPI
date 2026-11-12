using CompareShopAuthAPI.Infrastructure;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace CompareShopAuthAPI.Tests;

public sealed class AuthSettingsTests
{
    [Fact]
    public void TestingEnvironmentUsesConfiguredLimitAndDefaultForMissingLimit()
    {
        var settings = Create("Testing", new Dictionary<string, string?> { ["Throttle:Limit"] = "3", ["Enabled"] = "true" });

        Assert.Equal(3, settings.GetLimit("Throttle:Limit", 10));
        Assert.Equal(7, settings.GetLimit("Throttle:Missing", 7));
        Assert.Equal("true", settings.Get("Enabled"));
        Assert.True(settings.GetBoolean("Enabled"));
        Assert.False(settings.IsDevelopment);
    }

    [Fact]
    public void NonTestingEnvironmentUsesProductionLimitAndReportsDevelopment()
    {
        var production = Create("Production", new Dictionary<string, string?> { ["Throttle:Limit"] = "3" });
        var development = Create("Development", new Dictionary<string, string?>());

        Assert.Equal(10, production.GetLimit("Throttle:Limit", 10));
        Assert.False(production.IsDevelopment);
        Assert.True(development.IsDevelopment);
    }

    private static ConfigurationAuthSettings Create(string environmentName, IDictionary<string, string?> values)
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(values).Build();
        return new ConfigurationAuthSettings(configuration, new TestHostEnvironment(environmentName));
    }

    private sealed class TestHostEnvironment(string environmentName) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = environmentName;
        public string ApplicationName { get; set; } = "Tests";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
