using System.Text.Json;
using CompareShopAuthAPI.Data;
using CompareShopAuthAPI.Security;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using RabbitMQ.Client;
using Xunit;

namespace CompareShopAuthAPI.Tests;

public sealed class EmailMessagePublisherContractTests
{
    [Fact]
    public void VerificationTemplateDataUsesRendererTokenAndProducesUsableTarget()
    {
        const string syntheticToken = "synthetic-token_123";
        var templateData = CompareShopAuthAPI.Application.AuthApplicationUtilities.VerificationTemplateData(syntheticToken);

        Assert.Equal(new[] { "token" }, templateData.Keys.Order().ToArray());
        Assert.Equal(syntheticToken, templateData["token"]);

        var target = new Uri($"https://shop.example.test/verify-email?token={Uri.EscapeDataString(templateData["token"])}");
        Assert.Equal("https", target.Scheme);
        Assert.Equal("shop.example.test", target.Host);
        Assert.Equal("/verify-email", target.AbsolutePath);
        Assert.Equal(syntheticToken, target.Query["?token=".Length..]);
    }

    [Fact]
    public async Task OutboxEnqueueStoresEncryptedEmailApiV1Contract()
    {
        var options = new DbContextOptionsBuilder<AuthDbContext>()
            .UseInMemoryDatabase($"email-outbox-contract-{Guid.NewGuid():N}")
            .Options;
        var key = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        var protector = new SecretPayloadProtector(new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Outbox:EncryptionKey"] = key })
            .Build());
        var templateData = new Dictionary<string, string> { ["displayName"] = "Test User" };

        await using var db = new AuthDbContext(options);
        var outbox = new AuthEmailOutbox(db, protector, TimeProvider.System);
        outbox.Enqueue("person@example.test", "auth-verify", templateData);
        await db.SaveChangesAsync();

        var stored = await db.EmailOutbox.SingleAsync();
        var message = protector.Unprotect<EmailSendRequested>(stored.Nonce, stored.Ciphertext, stored.Tag);

        Assert.Equal(stored.RequestId, message.RequestId);
        Assert.Equal("EmailSendRequested", message.MessageType);
        Assert.Equal(1, message.Version);
        Assert.Equal("person@example.test", message.To);
        Assert.Equal("auth-verify", message.TemplateKey);
        Assert.Equal("vi", message.Locale);
        Assert.Equal("auth-verify", message.SubjectKey);
        Assert.Equal("Test User", message.TemplateData["displayName"]);
    }

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
        using var document = JsonDocument.Parse(transport.Body!);
        var root = document.RootElement;
        Assert.Equal(JsonValueKind.Object, root.ValueKind);
        Assert.Equal("EmailSendRequested", root.GetProperty("messageType").GetString());
        Assert.Equal(1, root.GetProperty("version").GetInt32());
        Assert.Equal(message.RequestId.ToString("D"), root.GetProperty("requestId").GetString());
        Assert.Equal("person@example.test", root.GetProperty("to").GetString());
        Assert.Equal("auth-verify", root.GetProperty("templateKey").GetString());
        Assert.Equal("vi", root.GetProperty("locale").GetString());
        Assert.Equal("auth-verify", root.GetProperty("subjectKey").GetString());
        Assert.Equal(JsonValueKind.Object, root.GetProperty("templateData").ValueKind);
        Assert.False(root.TryGetProperty("recipient", out _));

        var payload = JsonSerializer.Deserialize<EmailSendRequested>(transport.Body!);
        Assert.NotNull(payload);
        Assert.Equal("EmailSendRequested", payload.MessageType);
        Assert.Equal(message.RequestId, payload.RequestId);
        Assert.Equal(message.Version, payload.Version);
        Assert.Equal(message.To, payload.To);
        Assert.Equal(message.TemplateKey, payload.TemplateKey);
        Assert.Equal(message.Locale, payload.Locale);
        Assert.Equal(message.SubjectKey, payload.SubjectKey);
        Assert.Equal(message.TemplateData, payload.TemplateData);
    }

    [Fact]
    public async Task ResetPinPublisherEmitsEmailApiV1WireContract()
    {
        const string syntheticPin = "482913";
        var templateData = CompareShopAuthAPI.Application.AuthApplicationUtilities.ResetPinTemplateData(syntheticPin);
        var message = new EmailSendRequested("EmailSendRequested", Guid.NewGuid(), 1, "person@example.test", "auth-reset-password-pin", "vi", "auth-reset-password-pin", templateData);
        var transport = new RecordingTransport();
        var publisher = new RabbitMqEmailMessagePublisher(transport);

        await publisher.PublishAsync(message, CancellationToken.None);

        Assert.Equal("email-send-requests-publisher", transport.Exchange);
        Assert.Equal("email-send-requests", transport.RoutingKey);
        Assert.Equal(message.RequestId.ToString("D"), transport.Properties!.MessageId);
        Assert.True(transport.Properties.Persistent);
        Assert.Equal("application/json", transport.Properties.ContentType);
        using var document = JsonDocument.Parse(transport.Body!);
        var root = document.RootElement;
        Assert.Equal("EmailSendRequested", root.GetProperty("messageType").GetString());
        Assert.Equal(1, root.GetProperty("version").GetInt32());
        Assert.Equal(message.RequestId.ToString("D"), root.GetProperty("requestId").GetString());
        Assert.Equal("person@example.test", root.GetProperty("to").GetString());
        Assert.Equal("auth-reset-password-pin", root.GetProperty("templateKey").GetString());
        Assert.Equal("vi", root.GetProperty("locale").GetString());
        Assert.Equal("auth-reset-password-pin", root.GetProperty("subjectKey").GetString());
        var data = root.GetProperty("templateData");
        Assert.Equal("", data.GetProperty("displayName").GetString());
        Assert.Equal("10", data.GetProperty("expiresInMinutes").GetString());
        Assert.Equal("4 8 2 9 1 3", data.GetProperty("pinSpaced").GetString());
        Assert.Equal("482-913", data.GetProperty("pinGrouped").GetString());
        Assert.False(data.TryGetProperty("pin", out _));
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

    private static EmailSendRequested NewMessage() => new("EmailSendRequested", Guid.NewGuid(), 1, "person@example.test", "auth-verify", "vi", "auth-verify", new Dictionary<string, string>());

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
