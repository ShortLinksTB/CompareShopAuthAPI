using System.Text.Json;
using CompareShopAuthAPI.Data;
using CompareShopAuthAPI.Security;
using RabbitMQ.Client;
using Xunit;

namespace CompareShopAuthAPI.Tests;

public sealed class EmailMessagePublisherContractTests
{
    [Fact]
    public async Task PublishesVersionedPayloadToApprovedExchangeAndRouteWithoutQueueConfiguration()
    {
        var transport = new RecordingTransport();
        var publisher = new RabbitMqEmailMessagePublisher(transport);
        var message = NewMessage();

        await publisher.PublishAsync(message, CancellationToken.None);

        Assert.Equal("email-send-requests-publisher", transport.Exchange);
        Assert.Equal("email-send-requests", transport.RoutingKey);
        Assert.Equal(message.RequestId.ToString("D"), transport.Properties!.MessageId);
        Assert.True(transport.Properties.Persistent);
        Assert.Equal("application/json", transport.Properties.ContentType);
        var payload = JsonSerializer.Deserialize<EmailSendRequested>(transport.Body!);
        Assert.NotNull(payload);
        Assert.Equal(message.RequestId, payload.RequestId);
        Assert.Equal(message.Version, payload.Version);
        Assert.Equal(message.Recipient, payload.Recipient);
        Assert.Equal(message.TemplateKey, payload.TemplateKey);
        Assert.Equal(message.Locale, payload.Locale);
        Assert.Equal(message.SubjectKey, payload.SubjectKey);
        Assert.Equal(message.TemplateData, payload.TemplateData);
    }

    [Fact]
    public async Task WaitsForBrokerConfirmationAndPropagatesFailureForOutboxRetry()
    {
        var confirmation = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var transport = new RecordingTransport { PublishConfirmation = confirmation.Task };
        var publisher = new RabbitMqEmailMessagePublisher(transport);

        var publish = publisher.PublishAsync(NewMessage(), CancellationToken.None);
        Assert.False(publish.IsCompleted);
        confirmation.SetException(new HttpRequestException("broker did not confirm"));

        await Assert.ThrowsAsync<HttpRequestException>(() => publish);
    }

    private static EmailSendRequested NewMessage() => new(Guid.NewGuid(), 1, "person@example.test", "auth-verify", "vi", "auth-verify", new Dictionary<string, string>());

    private sealed class RecordingTransport : IEmailBrokerTransport
    {
        public string? Exchange { get; private set; }
        public string? RoutingKey { get; private set; }
        public BasicProperties? Properties { get; private set; }
        public byte[]? Body { get; private set; }
        public Task? PublishConfirmation { get; init; }

        public Task PublishAsync(string exchange, string routingKey, BasicProperties properties, ReadOnlyMemory<byte> body, CancellationToken cancellationToken)
        {
            Exchange = exchange;
            RoutingKey = routingKey;
            Properties = properties;
            Body = body.ToArray();
            return PublishConfirmation ?? Task.CompletedTask;
        }
    }
}
