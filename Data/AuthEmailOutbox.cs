using CompareShopAuthAPI.Security;
using CompareShopAuthAPI.Application;

namespace CompareShopAuthAPI.Data;

public sealed class AuthEmailOutbox(AuthDbContext db, SecretPayloadProtector protector, TimeProvider clock) : IAuthEmailOutboxPort
{
    public void Enqueue(string recipient, string template, Dictionary<string, string> data)
    {
        var requestId = Guid.NewGuid();
        var payload = new EmailSendRequested(requestId, 1, recipient, template, "vi", template, data);
        var encrypted = protector.Protect(payload);
        var now = clock.GetUtcNow();
        db.EmailOutbox.Add(new EmailOutboxMessage { RequestId = requestId, Nonce = encrypted.Nonce, Ciphertext = encrypted.Ciphertext, Tag = encrypted.Tag, CreatedAt = now, NextAttemptAt = now });
    }
}
