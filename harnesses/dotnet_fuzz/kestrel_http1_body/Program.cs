using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SharpFuzz;

namespace KestrelHttp1BodyFuzz;

internal static class Program
{
    private const int MaxInputLength = 64 * 1024;
    private const int MaxResponseLength = 64 * 1024;
    private const string SemanticRepairVariable = "TF_KESTREL_HTTP1_SEMANTIC_REPAIR";
    private static readonly TimeSpan IoTimeout = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan ResponseTimeout = TimeSpan.FromMilliseconds(100);
    private static readonly byte[] VictimRequest = Encoding.ASCII.GetBytes(
        "GET /__taintforge_victim__ HTTP/1.1\r\n" +
        "Host: localhost\r\n" +
        "Connection: close\r\n\r\n");

    private static WebApplication? s_application;
    private static IPEndPoint? s_endpoint;

    public static void Main(string[] args)
    {
        if (args.Length != 0)
        {
            Replay(args);
            return;
        }

        Fuzzer.OutOfProcess.Run(stream =>
        {
            var bytes = ReadBoundedInput(stream);
            if (bytes is null || bytes.Length == 0)
            {
                return;
            }

            var semanticRepair = StringComparer.Ordinal.Equals(
                    Environment.GetEnvironmentVariable(SemanticRepairVariable),
                    "1");
            if (semanticRepair)
            {
                bytes = SemanticHttp1Generator.Generate(bytes);
            }

            // SharpFuzz establishes AFL's fork server before invoking this callback. Starting
            // Kestrel here keeps its listener and worker threads in the fuzz child, so coverage
            // and failures belong to exactly this input instead of racing in the fork parent.
            StartServer();
            try
            {
                Exercise(
                    bytes,
                    suppressKnownBareLfHeaderDifferential: !semanticRepair,
                    observeCoverage: true);
            }
            finally
            {
                StopServer();
            }
        });
    }

    private static void Replay(string[] args)
    {
        if (args.Length != 2 ||
            (!StringComparer.Ordinal.Equals(args[0], "--replay") &&
             !StringComparer.Ordinal.Equals(args[0], "--replay-semantic") &&
             !StringComparer.Ordinal.Equals(args[0], "--render-semantic")))
        {
            throw new ArgumentException(
                "Usage: KestrelHttp1BodyFuzz --replay|--replay-semantic|--render-semantic INPUT");
        }

        var bytes = File.ReadAllBytes(args[1]);
        if (bytes.Length == 0 || bytes.Length > MaxInputLength)
        {
            throw new ArgumentOutOfRangeException(
                nameof(args),
                $"Replay input must contain between 1 and {MaxInputLength} bytes.");
        }

        var semantic = !StringComparer.Ordinal.Equals(args[0], "--replay");
        if (semantic)
        {
            bytes = SemanticHttp1Generator.Generate(bytes);
        }

        if (StringComparer.Ordinal.Equals(args[0], "--render-semantic"))
        {
            Console.WriteLine(Convert.ToBase64String(bytes));
            return;
        }

        StartServer();
        try
        {
            var result = Exercise(
                bytes,
                suppressKnownBareLfHeaderDifferential: !semantic,
                observeCoverage: false);
            Console.WriteLine(
                $"PASS semantic={semantic.ToString(CultureInfo.InvariantCulture).ToLowerInvariant()} " +
                $"request_bytes={bytes.Length} " +
                $"request_sha256={Convert.ToHexString(SHA256.HashData(bytes))} " +
                $"contiguous_bytes={result.Contiguous.ResponseLength} " +
                $"contiguous_timeout={result.Contiguous.TimedOut.ToString(CultureInfo.InvariantCulture).ToLowerInvariant()} " +
                $"segmented_bytes={result.Segmented?.ResponseLength.ToString(CultureInfo.InvariantCulture) ?? "skipped"} " +
                $"segmented_timeout={result.Segmented?.TimedOut.ToString(CultureInfo.InvariantCulture).ToLowerInvariant() ?? "skipped"} " +
                $"normalized_sha256={result.Contiguous.NormalizedSha256} " +
                $"normalized={result.Contiguous.NormalizedResponse.Replace("\r\n", " | ", StringComparison.Ordinal)}");
        }
        finally
        {
            StopServer();
        }
    }

    private static void StartServer()
    {
        var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions
        {
            Args = [],
            ApplicationName = typeof(Program).Assembly.GetName().Name,
            ContentRootPath = AppContext.BaseDirectory,
            EnvironmentName = "Production",
        });
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(options =>
        {
            options.AddServerHeader = false;
            options.Limits.KeepAliveTimeout = IoTimeout;
            options.Limits.RequestHeadersTimeout = IoTimeout;
            options.Limits.MaxRequestBodySize = MaxInputLength;
            options.Limits.MaxRequestBufferSize = 2 * MaxInputLength;
            options.Limits.MaxRequestHeadersTotalSize = MaxInputLength;
            options.Limits.MaxRequestLineSize = MaxInputLength;
            options.Limits.MinRequestBodyDataRate = null;
            options.Limits.MinResponseDataRate = null;
            options.Listen(IPAddress.Loopback, 0, listenOptions => listenOptions.Protocols = HttpProtocols.Http1);
        });

        var application = builder.Build();
        application.Run(HandleRequestAsync);
        application.StartAsync().GetAwaiter().GetResult();

        var expectedAssembly = Path.GetFullPath(
            Path.Combine(AppContext.BaseDirectory, "Microsoft.AspNetCore.Server.Kestrel.Core.dll"));
        var loadedAssembly = Path.GetFullPath(typeof(KestrelServerOptions).Assembly.Location);
        if (!StringComparer.Ordinal.Equals(expectedAssembly, loadedAssembly))
        {
            throw new InvalidOperationException(
                $"The body harness loaded Kestrel from '{loadedAssembly}', expected '{expectedAssembly}'.");
        }

        var server = application.Services.GetRequiredService<IServer>();
        var addresses = server.Features.Get<IServerAddressesFeature>()?.Addresses;
        var address = addresses?.SingleOrDefault()
            ?? throw new InvalidOperationException("Kestrel did not publish exactly one loopback address.");
        var uri = new Uri(address);
        if (!IPAddress.TryParse(uri.Host, out var host) || !IPAddress.IsLoopback(host))
        {
            throw new InvalidOperationException($"Refusing to fuzz a non-loopback endpoint: {address}");
        }

        s_application = application;
        s_endpoint = new IPEndPoint(host, uri.Port);
    }

    private static void StopServer()
    {
        var application = s_application;
        s_application = null;
        s_endpoint = null;

        if (application is null)
        {
            return;
        }

        using var timeout = new CancellationTokenSource(IoTimeout);
        application.StopAsync(timeout.Token).GetAwaiter().GetResult();
        application.DisposeAsync().AsTask().GetAwaiter().GetResult();
    }

    private static async Task HandleRequestAsync(HttpContext context)
    {
        long bodyLength = 0;
        using var bodyHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

        var appMode = Int32.TryParse(
            context.Request.Headers["X-TF-App-Mode"].ToString(),
            NumberStyles.None,
            CultureInfo.InvariantCulture,
            out var parsedAppMode)
            ? parsedAppMode
            : 0;

        switch (appMode)
        {
            case 0:
                while (true)
                {
                    var result = await context.Request.BodyReader.ReadAsync(context.RequestAborted);
                    bodyLength += result.Buffer.Length;
                    foreach (var segment in result.Buffer)
                    {
                        bodyHash.AppendData(segment.Span);
                    }
                    context.Request.BodyReader.AdvanceTo(result.Buffer.End);

                    if (result.IsCompleted)
                    {
                        break;
                    }
                }
                break;
            case 1:
                // Return without touching the body. Kestrel must produce the response, drain the
                // declared request boundary, and only then parse the fixed victim request.
                break;
            case 2:
                var oneByte = new byte[1];
                var bytesRead = await context.Request.Body.ReadAsync(oneByte, context.RequestAborted);
                if (bytesRead != 0)
                {
                    bodyLength = bytesRead;
                    bodyHash.AppendData(oneByte.AsSpan(0, bytesRead));
                }
                break;
            case 3:
                bodyLength = await ReadPartialPipeAsync(context, consumeOneByte: true, bodyHash);
                break;
            case 4:
                bodyLength = await ReadPartialPipeAsync(context, consumeOneByte: false, bodyHash);
                break;
        }

        var requestFeature = context.Features.Get<IHttpRequestFeature>();
        var requestIdentity = String.Join(
            '\n',
            context.Request.Method,
            context.Request.Protocol,
            requestFeature?.RawTarget ?? String.Empty);

        var trailers = new StringBuilder();
        var trailersFeature = context.Features.Get<IHttpRequestTrailersFeature>();
        if (trailersFeature?.Available == true)
        {
            foreach (var trailer in trailersFeature.Trailers.OrderBy(
                item => item.Key,
                StringComparer.OrdinalIgnoreCase))
            {
                trailers.Append(trailer.Key.ToLowerInvariant()).Append(':');
                foreach (var value in trailer.Value.OrderBy(value => value, StringComparer.Ordinal))
                {
                    trailers.Append(value).Append('\0');
                }
                trailers.Append('\n');
            }
        }

        context.Response.StatusCode = StatusCodes.Status204NoContent;
        context.Response.ContentLength = 0;
        context.Response.Headers["X-TaintForge-App-Mode"] = appMode.ToString(CultureInfo.InvariantCulture);
        context.Response.Headers["X-TaintForge-Body-Length"] = bodyLength.ToString(CultureInfo.InvariantCulture);
        context.Response.Headers["X-TaintForge-Body-Sha256"] = Convert.ToHexString(bodyHash.GetHashAndReset());
        context.Response.Headers["X-TaintForge-Request-Sha256"] = Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes(requestIdentity)));
        context.Response.Headers["X-TaintForge-Trailers-Sha256"] = Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes(trailers.ToString())));
    }

    private static async Task<int> ReadPartialPipeAsync(
        HttpContext context,
        bool consumeOneByte,
        IncrementalHash bodyHash)
    {
        var result = await context.Request.BodyReader.ReadAsync(context.RequestAborted);
        var buffer = result.Buffer;
        var consumed = buffer.Start;

        if (consumeOneByte && !buffer.IsEmpty)
        {
            var firstByte = buffer.FirstSpan[0];
            bodyHash.AppendData(new byte[] { firstByte });
            consumed = buffer.GetPosition(1);
        }

        // Examining all available body bytes while consuming less is a supported PipeReader
        // pattern. Returning now transfers the exact remaining boundary to Kestrel's automatic
        // drain path and stresses its _examinedUnconsumedBytes bookkeeping.
        context.Request.BodyReader.AdvanceTo(consumed, buffer.End);
        return consumed.Equals(buffer.Start) ? 0 : 1;
    }

    private static byte[]? ReadBoundedInput(Stream stream)
    {
        using var input = new MemoryStream();
        var buffer = new byte[8192];

        while (true)
        {
            var read = stream.Read(buffer, 0, buffer.Length);
            if (read == 0)
            {
                return input.ToArray();
            }

            if (input.Length + read > MaxInputLength)
            {
                return null;
            }

            input.Write(buffer, 0, read);
        }
    }

    private static OracleResult Exercise(
        byte[] request,
        bool suppressKnownBareLfHeaderDifferential,
        bool observeCoverage)
    {
        var endpoint = s_endpoint;
        if (s_application?.Lifetime.ApplicationStopping.IsCancellationRequested != false || endpoint is null)
        {
            throw new InvalidOperationException("The in-process Kestrel server stopped unexpectedly.");
        }

        var transcript = AppendVictimRequest(request);
        var contiguous = Exchange(endpoint, transcript, segmented: false);

        // Raw bytes can reproduce a separately preserved, stock-network-confirmed bare-LF
        // short-header family. Semantic transcripts always use CRLF request headers, while their
        // binary bodies may legitimately contain 0x0a, so never suppress their segmented oracle.
        if (suppressKnownBareLfHeaderDifferential && ContainsBareLineFeed(request))
        {
            ObserveCoverage(contiguous, segmented: null, observeCoverage);
            return new OracleResult(contiguous, Segmented: null);
        }

        var segmented = Exchange(endpoint, transcript, segmented: true);
        // ReceiveResponse uses a short deadline to keep malformed/incomplete requests from
        // stalling the campaign. A timeout yields only a partial observation, not a completed
        // response stream, so it cannot prove a segmentation differential. Keep those inputs in
        // normal coverage and reserve the crash oracle for two complete, unequal transcripts.
        if (!contiguous.TimedOut &&
            !segmented.TimedOut &&
            !StringComparer.Ordinal.Equals(contiguous.NormalizedResponse, segmented.NormalizedResponse))
        {
            throw new InvalidDataException(
                "Kestrel HTTP/1 response-stream segmentation divergence. " +
                $"contiguous={contiguous.NormalizedResponse}; segmented={segmented.NormalizedResponse}");
        }

        ObserveCoverage(contiguous, segmented, observeCoverage);
        return new OracleResult(contiguous, segmented);
    }

    private static void ObserveCoverage(
        ExchangeResult contiguous,
        ExchangeResult? segmented,
        bool observeCoverage)
    {
        if (!observeCoverage)
        {
            return;
        }

        // Only this synchronous post-exchange classifier is SharpFuzz-instrumented. Kestrel
        // processes requests on worker threads, where target-assembly instrumentation produced
        // highly variable maps and non-stock SIGINT families. Keep the product DLL pristine and
        // guide AFL with stable protocol outcomes that matter to this lane instead.
        // Observe projects the combination-sensitive fingerprint onto AFL's bitmap itself.
        _ = OutcomeCoverage.Observe(contiguous.NormalizedResponse, segmented is not null);
    }

    private static ExchangeResult Exchange(IPEndPoint endpoint, byte[] request, bool segmented)
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)
        {
            NoDelay = true,
            ReceiveTimeout = (int)ResponseTimeout.TotalMilliseconds,
            SendTimeout = (int)IoTimeout.TotalMilliseconds,
            LingerState = new LingerOption(enable: true, seconds: 0),
        };

        socket.Connect(endpoint);

        try
        {
            if (segmented)
            {
                SendSegmented(socket, request);
            }
            else
            {
                SendAll(socket, request);
            }
        }
        catch (SocketException ex) when (IsExpectedPeerClose(ex.SocketErrorCode))
        {
            // A rejected request may close while a segmented sender still has bytes queued.
        }

        var response = ReceiveResponse(socket);
        var normalized = NormalizeResponse(response.Bytes);
        return new ExchangeResult(
            ResponseLength: response.Bytes.Length,
            TimedOut: response.TimedOut,
            NormalizedResponse: normalized,
            NormalizedSha256: Convert.ToHexString(SHA256.HashData(Encoding.Latin1.GetBytes(normalized))));
    }

    private static byte[] AppendVictimRequest(byte[] request)
    {
        var transcript = GC.AllocateUninitializedArray<byte>(request.Length + VictimRequest.Length);
        request.CopyTo(transcript, 0);
        VictimRequest.CopyTo(transcript, request.Length);
        return transcript;
    }

    private static void SendAll(Socket socket, ReadOnlySpan<byte> bytes)
    {
        while (!bytes.IsEmpty)
        {
            var sent = socket.Send(bytes, SocketFlags.None);
            if (sent == 0)
            {
                return;
            }

            bytes = bytes[sent..];
        }
    }

    private static void SendSegmented(Socket socket, byte[] bytes)
    {
        const int maxSegments = 64;
        var boundaries = new SortedSet<int>();

        // Prioritize protocol delimiters, then add evenly distributed data-dependent cuts so
        // bodies and pipelined victim requests are not left as one opaque final write.
        for (var i = 1; i < bytes.Length; i++)
        {
            if (bytes[i - 1] is (byte)'\r' or (byte)'\n' or (byte)':' ||
                bytes[i] is (byte)'\r' or (byte)'\n')
            {
                boundaries.Add(i);
            }
        }

        for (var i = 1; i < 17 && bytes.Length > 1; i++)
        {
            var baseOffset = (int)((long)bytes.Length * i / 17);
            var adjustment = bytes[(i * 131) % bytes.Length] % 7 - 3;
            boundaries.Add(Math.Clamp(baseOffset + adjustment, 1, bytes.Length - 1));
        }

        var selected = boundaries.Count < maxSegments
            ? boundaries.ToArray()
            : boundaries.Where((_, index) => index % Math.Max(1, boundaries.Count / (maxSegments - 1)) == 0)
                .Take(maxSegments - 1)
                .ToArray();

        var offset = 0;
        foreach (var boundary in selected)
        {
            SendAll(socket, bytes.AsSpan(offset, boundary - offset));
            offset = boundary;
        }
        SendAll(socket, bytes.AsSpan(offset));
    }

    private static ReceiveResult ReceiveResponse(Socket socket)
    {
        Span<byte> response = stackalloc byte[4096];
        using var output = new MemoryStream();
        var timedOut = false;

        try
        {
            while (output.Length < MaxResponseLength)
            {
                var remaining = MaxResponseLength - (int)output.Length;
                var received = socket.Receive(response[..Math.Min(response.Length, remaining)], SocketFlags.None);
                if (received == 0)
                {
                    break;
                }

                output.Write(response[..received]);
            }
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.TimedOut)
        {
            timedOut = true;
        }
        catch (SocketException ex) when (IsExpectedPeerClose(ex.SocketErrorCode))
        {
            // Keep any complete response bytes observed before a normal peer close.
        }

        return new ReceiveResult(output.ToArray(), timedOut);
    }

    private static string NormalizeResponse(byte[] response)
    {
        var text = Encoding.Latin1.GetString(response);
        var normalized = new StringBuilder();
        var cursor = 0;

        while (cursor < text.Length)
        {
            var headerEnd = text.IndexOf("\r\n\r\n", cursor, StringComparison.Ordinal);
            if (headerEnd < 0)
            {
                AppendResidual(normalized, response.AsSpan(cursor));
                break;
            }

            var lines = text[cursor..headerEnd].Split("\r\n", StringSplitOptions.None);
            if (lines.Length == 0 || !lines[0].StartsWith("HTTP/", StringComparison.Ordinal))
            {
                AppendResidual(normalized, response.AsSpan(cursor));
                break;
            }

            var statusCode = ParseStatusCode(lines[0]);
            var contentLength = 0;
            var headers = new List<string>();
            foreach (var line in lines.Skip(1))
            {
                var separator = line.IndexOf(':');
                if (separator <= 0)
                {
                    headers.Add(line);
                    continue;
                }

                var name = line[..separator].Trim();
                var value = line[(separator + 1)..].Trim();
                if (name.Equals("Date", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (name.Equals("Content-Length", StringComparison.OrdinalIgnoreCase))
                {
                    _ = Int32.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out contentLength);
                }

                headers.Add($"{name.ToLowerInvariant()}:{value}");
            }

            cursor = headerEnd + 4;
            if (statusCode is >= 100 and < 200)
            {
                // Whether Kestrel emits 100-continue before an already-buffered body is a timing
                // optimization, not a framing decision. Compare only final responses.
                continue;
            }

            normalized.Append(lines[0]).Append("\r\n");
            foreach (var header in headers.OrderBy(value => value, StringComparer.Ordinal))
            {
                normalized.Append(header).Append("\r\n");
            }

            if (contentLength > 0)
            {
                var available = Math.Min(contentLength, response.Length - cursor);
                var body = response.AsSpan(cursor, available);
                normalized.Append("body-length:").Append(available).Append("\r\n")
                    .Append("body-sha256:").Append(Convert.ToHexString(SHA256.HashData(body))).Append("\r\n");
                cursor += available;
                if (available != contentLength)
                {
                    normalized.Append("body-truncated\r\n");
                    break;
                }
            }

            normalized.Append("\r\n");
        }

        return normalized.ToString();
    }

    private static int ParseStatusCode(string statusLine)
    {
        var firstSpace = statusLine.IndexOf(' ');
        if (firstSpace < 0 || statusLine.Length < firstSpace + 4)
        {
            return 0;
        }

        return Int32.TryParse(
            statusLine.AsSpan(firstSpace + 1, 3),
            NumberStyles.None,
            CultureInfo.InvariantCulture,
            out var statusCode)
            ? statusCode
            : 0;
    }

    private static void AppendResidual(StringBuilder normalized, ReadOnlySpan<byte> residual)
    {
        normalized.Append("residual-length:").Append(residual.Length).Append("\r\n")
            .Append("residual-sha256:").Append(Convert.ToHexString(SHA256.HashData(residual))).Append("\r\n");
    }

    private static bool ContainsBareLineFeed(ReadOnlySpan<byte> bytes)
    {
        for (var i = 0; i < bytes.Length; i++)
        {
            if (bytes[i] == (byte)'\n' && (i == 0 || bytes[i - 1] != (byte)'\r'))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsExpectedPeerClose(SocketError error) => error is
        SocketError.ConnectionAborted or
        SocketError.ConnectionReset or
        SocketError.Disconnecting or
        SocketError.NetworkReset or
        SocketError.NotConnected or
        SocketError.OperationAborted or
        SocketError.Shutdown or
        SocketError.TimedOut;

    private readonly record struct ExchangeResult(
        int ResponseLength,
        bool TimedOut,
        string NormalizedResponse,
        string NormalizedSha256);

    private readonly record struct ReceiveResult(byte[] Bytes, bool TimedOut);

    private readonly record struct OracleResult(
        ExchangeResult Contiguous,
        ExchangeResult? Segmented);
}

internal static class OutcomeCoverage
{
    private const string VictimRequestHash =
        "348D4EF711E1516E284C63CB2EDC3F6C72BAB139B6667A7FDADC8F39475E920D";
    private const string EmptySha256 =
        "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855";

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static int Observe(string normalizedResponse, bool segmented)
    {
        ArgumentNullException.ThrowIfNull(normalizedResponse);

        var fingerprint = segmented ? 17 : 31;
        var responseCount = 0;

        foreach (var line in normalizedResponse.Split("\r\n", StringSplitOptions.None))
        {
            if (line.StartsWith("HTTP/", StringComparison.Ordinal))
            {
                responseCount++;
                fingerprint = Mix(fingerprint, ClassifyStatus(line));
            }
            else if (line.StartsWith("x-taintforge-app-mode:", StringComparison.Ordinal))
            {
                fingerprint = Mix(fingerprint, ClassifyAppMode(line));
            }
            else if (line.StartsWith("x-taintforge-body-length:", StringComparison.Ordinal))
            {
                fingerprint = Mix(fingerprint, ClassifyBodyLength(line));
                fingerprint = Mix(fingerprint, ExactBodyLength(line));
            }
            else if (line.StartsWith("x-taintforge-request-sha256:", StringComparison.Ordinal))
            {
                // Which request Kestrel believed it parsed, in arrival order. A framing error
                // that shifts the cross-request boundary changes this value while every
                // bucketed feature above stays identical, so it is the decisive desync
                // observable and must reach the fingerprint.
                fingerprint = Mix(fingerprint, ClassifyRequestIdentity(line));
            }
            else if (line.StartsWith("residual-length:", StringComparison.Ordinal))
            {
                fingerprint = Mix(fingerprint, ClassifyResidualLength(line));
            }
        }

        fingerprint = Mix(
            fingerprint,
            responseCount switch
            {
                0 => 101,
                1 => 103,
                2 => 107,
                3 => 109,
                _ => 113,
            });

        if (normalizedResponse.Contains(VictimRequestHash, StringComparison.Ordinal))
        {
            fingerprint = Mix(fingerprint, 127);
        }

        if (normalizedResponse.Contains("residual-length:", StringComparison.Ordinal))
        {
            fingerprint = Mix(fingerprint, 131);
        }

        if (normalizedResponse.Contains("body-truncated", StringComparison.Ordinal))
        {
            fingerprint = Mix(fingerprint, 137);
        }

        if (normalizedResponse.Contains(
                $"x-taintforge-trailers-sha256:{EmptySha256}",
                StringComparison.Ordinal))
        {
            fingerprint = Mix(fingerprint, 139);
        }
        else if (normalizedResponse.Contains("x-taintforge-trailers-sha256:", StringComparison.Ordinal))
        {
            fingerprint = Mix(fingerprint, 149);
        }

        Project(fingerprint);
        return fingerprint;
    }

    // AFL's bitmap is a union of edges, so the classifier's independent feature branches can
    // never express which *combination* of protocol outcomes an input produced. Two inputs whose
    // only difference is a shifted cross-request boundary lit an identical map and the second was
    // discarded. Give every distinct fingerprint its own bitmap slot instead. The width bounds
    // both the coverage this lane can report and the corpus it can grow.
    private const uint ProjectionSlots = 4096;

    // Resolved by name on first use: a direct SharpFuzz.Common.Trace member reference makes the
    // SharpFuzz instrumenter reject this assembly as "already instrumented", which would silently
    // drop all of the classifier's own coverage.
    private static unsafe byte* s_sharedMem;
    private static bool s_sharedMemResolved;

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static unsafe void Project(int fingerprint)
    {
        if (!s_sharedMemResolved)
        {
            s_sharedMemResolved = true;
            var field = Type
                .GetType("SharpFuzz.Common.Trace, SharpFuzz.Common")
                ?.GetField("SharedMem", BindingFlags.Public | BindingFlags.Static);
            if (field?.GetValue(null) is { } boxed)
            {
                s_sharedMem = (byte*)Pointer.Unbox(boxed);
            }
        }

        var shared = s_sharedMem;
        if (shared == null)
        {
            // Not running under AFL (replay/triage); there is no bitmap to mark.
            return;
        }

        var mixed = (uint)fingerprint;
        mixed ^= mixed >> 16;
        mixed *= 2246822507u;
        mixed ^= mixed >> 13;
        mixed *= 3266489909u;
        mixed ^= mixed >> 16;

        shared[mixed % ProjectionSlots]++;
    }

    // Pooled-buffer and framing boundary shifts move the consumed body boundary by a handful of
    // bytes. ClassifyBodyLength's buckets hide exactly that, so keep the low range byte-exact and
    // only quantize above it.
    private static int ExactBodyLength(string line)
    {
        if (!Int64.TryParse(
                line.AsSpan("x-taintforge-body-length:".Length),
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out var length))
        {
            return 311;
        }

        return length <= 512
            ? 1024 + (int)length
            : 2048 + (int)Math.Min(length >> 6, 1023);
    }

    private static int ClassifyRequestIdentity(string line)
    {
        var value = line.AsSpan("x-taintforge-request-sha256:".Length);
        var digest = 2166136261u;
        foreach (var character in value)
        {
            digest = (digest ^ character) * 16777619u;
        }

        return unchecked((int)(0x10000u | (digest & 0xFFFFu)));
    }

    // Residual bytes are the ones Kestrel left unparsed on the connection: how many survived a
    // framing error separates a clean rejection from a boundary the server mis-advanced.
    private static int ClassifyResidualLength(string line)
    {
        if (!Int32.TryParse(
                line.AsSpan("residual-length:".Length),
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out var length))
        {
            return 313;
        }

        return 0x20000 + Math.Min(length, 2048);
    }

    private static int ClassifyStatus(string statusLine)
    {
        var firstSpace = statusLine.IndexOf(' ');
        if (firstSpace < 0 || statusLine.Length < firstSpace + 4 ||
            !Int32.TryParse(
                statusLine.AsSpan(firstSpace + 1, 3),
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out var statusCode))
        {
            return 151;
        }

        return statusCode switch
        {
            StatusCodes.Status100Continue => 157,
            StatusCodes.Status204NoContent => 163,
            StatusCodes.Status400BadRequest => 167,
            StatusCodes.Status408RequestTimeout => 173,
            StatusCodes.Status411LengthRequired => 179,
            StatusCodes.Status413PayloadTooLarge => 181,
            StatusCodes.Status414UriTooLong => 191,
            StatusCodes.Status431RequestHeaderFieldsTooLarge => 193,
            StatusCodes.Status500InternalServerError => 197,
            StatusCodes.Status501NotImplemented => 199,
            StatusCodes.Status505HttpVersionNotsupported => 211,
            _ => 223,
        };
    }

    private static int ClassifyAppMode(string line)
    {
        var value = line.AsSpan("x-taintforge-app-mode:".Length);
        return value switch
        {
            "0" => 227,
            "1" => 229,
            "2" => 233,
            "3" => 239,
            "4" => 241,
            _ => 251,
        };
    }

    private static int ClassifyBodyLength(string line)
    {
        if (!Int64.TryParse(
                line.AsSpan("x-taintforge-body-length:".Length),
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out var length))
        {
            return 257;
        }

        return length switch
        {
            0 => 263,
            1 => 269,
            <= 255 => 271,
            <= 2047 => 277,
            <= 4095 => 281,
            <= 8191 => 283,
            <= 16383 => 293,
            _ => 307,
        };
    }

    private static int Mix(int current, int value) => unchecked((current * 397) ^ value);
}
