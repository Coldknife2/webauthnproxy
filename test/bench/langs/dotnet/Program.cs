using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;

var builder = WebApplication.CreateSlimBuilder(args);
builder.Logging.ClearProviders();
var app = builder.Build();
byte[] secret = Encoding.UTF8.GetBytes("bench-secret-0123456789abcdef0123456789");

app.MapGet("/_wap/verify", (HttpContext c) =>
{
    string host = c.Request.Headers["X-Forwarded-Host"].ToString().ToLowerInvariant();
    if (host != "app.example.com") return Results.StatusCode(403);
    string? tok = null;
    foreach (var part in c.Request.Headers.Cookie.ToString().Split(';'))
        if (part.Trim().StartsWith("wap_session=")) tok = part.Trim()["wap_session=".Length..];
    if (tok is null) return Results.StatusCode(401);
    int i = tok.LastIndexOf('.');
    if (i < 0) return Results.StatusCode(401);
    string payload = tok[..i];
    byte[] want = HMACSHA256.HashData(secret, Encoding.UTF8.GetBytes("s|" + payload));
    byte[] got;
    try { got = Base64Url.DecodeFromChars(tok.AsSpan(i + 1)); } catch { return Results.StatusCode(401); }
    if (!CryptographicOperations.FixedTimeEquals(want, got)) return Results.StatusCode(401);
    var f = payload.Split('.');
    if (f.Length != 4 || long.Parse(f[2]) < DateTimeOffset.UtcNow.ToUnixTimeSeconds()) return Results.StatusCode(401);
    if (Encoding.UTF8.GetString(Base64Url.DecodeFromChars(f[1])) != host) return Results.StatusCode(401);
    string user = Encoding.UTF8.GetString(Base64Url.DecodeFromChars(f[0]));
    if (user != "bench") return Results.StatusCode(401); // user lookup (in-memory set of one)
    c.Response.Headers["X-Authenticated-User"] = user;
    return Results.StatusCode(200);
});
app.Run("http://0.0.0.0:8080");
