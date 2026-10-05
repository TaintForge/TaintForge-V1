using System.Net;
using Microsoft.AspNetCore.Server.Kestrel.Core;

var builder = WebApplication.CreateBuilder(args);

builder.WebHost.ConfigureKestrel(options =>
{
    options.Listen(IPAddress.Loopback, 5001, listenOptions =>
    {
        // Cleartext endpoints must select HTTP/2 explicitly because there is no ALPN.
        listenOptions.Protocols = HttpProtocols.Http2;
    });
});

var app = builder.Build();

Console.WriteLine($"KestrelCoreAssembly={typeof(KestrelServerOptions).Assembly.Location}");
Console.WriteLine($"KestrelCoreVersion={typeof(KestrelServerOptions).Assembly.GetName().Version}");

app.Run(async context =>
{
    long bytesRead = 0;
    var buffer = new byte[16 * 1024];
    int read;
    while ((read = await context.Request.Body.ReadAsync(buffer)) != 0)
    {
        bytesRead += read;
    }

    context.Response.ContentType = "text/plain";
    await context.Response.WriteAsync($"read={bytesRead}\n");
});

await app.RunAsync();
