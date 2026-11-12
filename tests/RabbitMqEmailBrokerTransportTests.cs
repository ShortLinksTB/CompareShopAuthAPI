using System.Reflection;
using CompareShopAuthAPI.Data;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using RabbitMQ.Client;
using Xunit;

namespace CompareShopAuthAPI.Tests;

public sealed class RabbitMqEmailBrokerTransportTests
{
    [Fact]
    public async Task PublishesThroughConfirmEnabledChannelWithoutDeclaringQueue()
    {
        var channel = FakeChannel.Create();
        var connection = FakeConnection.Create(channel.Proxy);
        ConnectionFactory? observedFactory = null;
        await using var transport = CreateTransport((factory, _) =>
        {
            observedFactory = factory;
            return Task.FromResult(connection.Proxy);
        });
        var properties = new BasicProperties { Persistent = true, MessageId = Guid.NewGuid().ToString("D") };
        byte[] payload = [1, 2, 3];

        await transport.PublishAsync("email-send-requests-publisher", "email-send-requests", properties, payload, CancellationToken.None);

        Assert.Equal("broker.test", observedFactory!.HostName);
        Assert.Equal("publisher-user", observedFactory.UserName);
        Assert.Equal("publisher-password", observedFactory.Password);
        Assert.True(connection.ChannelOptions!.PublisherConfirmationsEnabled);
        Assert.True(connection.ChannelOptions.PublisherConfirmationTrackingEnabled);
        Assert.Equal("email-send-requests-publisher", channel.Exchange);
        Assert.Equal("email-send-requests", channel.RoutingKey);
        Assert.True(channel.Mandatory);
        Assert.Same(properties, channel.Properties);
        Assert.Equal(payload, channel.Body);
        Assert.Contains("BasicPublishAsync", channel.Calls);
        Assert.DoesNotContain("QueueDeclareAsync", channel.Calls);
    }

    [Fact]
    public async Task BrokerNackIsPropagatedAndConnectionIsResetForOutboxRetry()
    {
        var channel = FakeChannel.Create(new HttpRequestException("broker did not confirm"));
        var connection = FakeConnection.Create(channel.Proxy);
        await using var transport = CreateTransport((_, _) => Task.FromResult(connection.Proxy));

        await Assert.ThrowsAsync<HttpRequestException>(() => transport.PublishAsync(
            "email-send-requests-publisher", "email-send-requests", new BasicProperties(), new byte[] { 4 }, CancellationToken.None));

        Assert.True(channel.Disposed);
        Assert.True(connection.Disposed);
    }

    [Fact]
    public async Task MissingConnectionConfigurationFailsBeforeConnecting()
    {
        var called = false;
        await using var transport = CreateTransport((_, _) =>
        {
            called = true;
            return Task.FromResult(FakeConnection.Create(FakeChannel.Create().Proxy).Proxy);
        }, new Dictionary<string, string?> { ["RabbitMQ:Host"] = "broker.test" });

        await Assert.ThrowsAsync<InvalidOperationException>(() => transport.PublishAsync(
            "email-send-requests-publisher", "email-send-requests", new BasicProperties(), ReadOnlyMemory<byte>.Empty, CancellationToken.None));
        Assert.False(called);
    }

    [Fact]
    public async Task ConnectionFailureCanBeRetriedWithFreshConnection()
    {
        var channel = FakeChannel.Create();
        var connection = FakeConnection.Create(channel.Proxy);
        var attempts = 0;
        await using var transport = CreateTransport((_, _) =>
        {
            attempts++;
            return attempts == 1
                ? Task.FromException<IConnection>(new IOException("temporary connection failure"))
                : Task.FromResult(connection.Proxy);
        });

        await Assert.ThrowsAsync<IOException>(() => transport.PublishAsync(
            "email-send-requests-publisher", "email-send-requests", new BasicProperties(), ReadOnlyMemory<byte>.Empty, CancellationToken.None));
        await transport.PublishAsync(
            "email-send-requests-publisher", "email-send-requests", new BasicProperties(), ReadOnlyMemory<byte>.Empty, CancellationToken.None);

        Assert.Equal(2, attempts);
        Assert.Equal(1, channel.PublishCount);
    }

    private static RabbitMqEmailBrokerTransport CreateTransport(
        Func<ConnectionFactory, CancellationToken, Task<IConnection>> createConnection,
        IDictionary<string, string?>? values = null)
    {
        values ??= new Dictionary<string, string?>
        {
            ["RabbitMQ:Host"] = "broker.test",
            ["RabbitMQ:Username"] = "publisher-user",
            ["RabbitMQ:Password"] = "publisher-password"
        };
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(values).Build();
        return new RabbitMqEmailBrokerTransport(configuration, NullLogger<RabbitMqEmailBrokerTransport>.Instance, createConnection);
    }

    public class FakeConnection : DispatchProxy
    {
        private IChannel channel = null!;
        public IConnection Proxy => (IConnection)(object)this;
        public CreateChannelOptions? ChannelOptions { get; private set; }
        public bool Disposed { get; private set; }

        public static FakeConnection Create(IChannel channel)
        {
            var proxy = DispatchProxy.Create<IConnection, FakeConnection>();
            var implementation = (FakeConnection)(object)proxy;
            implementation.channel = channel;
            return implementation;
        }

        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
        {
            switch (targetMethod!.Name)
            {
                case "CreateChannelAsync":
                    ChannelOptions = (CreateChannelOptions)args![0]!;
                    return Task.FromResult(channel);
                case "DisposeAsync":
                    Disposed = true;
                    return ValueTask.CompletedTask;
                case "ToString": return nameof(FakeConnection);
                default: throw new NotSupportedException(targetMethod.Name);
            }
        }
    }

    public class FakeChannel : DispatchProxy
    {
        private Exception? publishFailure;
        public IChannel Proxy => (IChannel)(object)this;
        public string? Exchange { get; private set; }
        public string? RoutingKey { get; private set; }
        public bool Mandatory { get; private set; }
        public BasicProperties? Properties { get; private set; }
        public byte[]? Body { get; private set; }
        public int PublishCount { get; private set; }
        public bool Disposed { get; private set; }
        public List<string> Calls { get; } = [];

        public static FakeChannel Create(Exception? publishFailure = null)
        {
            var proxy = DispatchProxy.Create<IChannel, FakeChannel>();
            var implementation = (FakeChannel)(object)proxy;
            implementation.Initialize(publishFailure);
            return implementation;
        }

        private void Initialize(Exception? failure)
        {
            publishFailure = failure;
        }

        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
        {
            Calls.Add(targetMethod!.Name);
            switch (targetMethod.Name)
            {
                case "get_IsOpen": return true;
                case "BasicPublishAsync":
                    PublishCount++;
                    Exchange = (string)args![0]!;
                    RoutingKey = (string)args[1]!;
                    Mandatory = (bool)args[2]!;
                    Properties = (BasicProperties)args[3]!;
                    Body = ((ReadOnlyMemory<byte>)args[4]!).ToArray();
                    return publishFailure is null ? ValueTask.CompletedTask : ValueTask.FromException(publishFailure);
                case "DisposeAsync":
                    Disposed = true;
                    return ValueTask.CompletedTask;
                case "ToString": return nameof(FakeChannel);
                default: throw new NotSupportedException(targetMethod.Name);
            }
        }
    }
}
