using System.Security.Cryptography;
using System.Text;

var builder = WebApplication.CreateSlimBuilder(args);
builder.Logging.ClearProviders();
var app = builder.Build();

// Same algorithm as the application: SHA-256 of the cookie value, lookup in a table of sessions (one entry, seeded at
// start), audience and expiry checks, user lookup.
const string token = "benchAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
var table = new Dictionary<string, (string User, string Aud, long Exp)>
{
    [Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)))] = ("bench", "app.example.com", DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 86400),
};
var users = new HashSet<string> { "bench" };

app.MapGet("/_wap/verify", (HttpContext c) =>
{
    string host = c.Request.Headers["X-Forwarded-Host"].ToString().ToLowerInvariant();
    if (host != "app.example.com") return Results.StatusCode(403);
    string? tok = null;
    foreach (var part in c.Request.Headers.Cookie.ToString().Split(';'))
        if (part.Trim().StartsWith("wap_session=")) tok = part.Trim()["wap_session=".Length..];
    if (tok is null) return Results.StatusCode(401);
    if (!table.TryGetValue(Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(tok))), out var s)) return Results.StatusCode(401);
    if (s.Aud != host || s.Exp < DateTimeOffset.UtcNow.ToUnixTimeSeconds() || !users.Contains(s.User)) return Results.StatusCode(401);
    c.Response.Headers["X-Authenticated-User"] = s.User;
    return Results.StatusCode(200);
});
app.Run("http://0.0.0.0:8080");
