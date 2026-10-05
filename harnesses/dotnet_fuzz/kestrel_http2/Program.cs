using System.Buffers.Binary;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
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
using Microsoft.AspNetCore.Server.Kestrel.Core.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SharpFuzz;

namespace KestrelHttp2Fuzz;

internal static class Program
{
    private const int MaxDecisionLength = 4096;
    private const int MaxResponsePayloadLength = 1024 * 1024;
    private const int MaxAccumulatedResponseData = 64 * 1024;
    private const byte DataFrame = 0x0;
    private const byte HeadersFrame = 0x1;
    private const byte RstStreamFrame = 0x3;
    private const byte SettingsFrame = 0x4;
    private const byte PingFrame = 0x6;
    private const byte GoAwayFrame = 0x7;
    private const byte WindowUpdateFrame = 0x8;
    private const byte Ack = 0x1;
    private const byte EndStream = 0x1;
    private const byte Padded = 0x8;
    private static readonly TimeSpan HandshakeTimeout = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan ExchangeTimeout = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan ShutdownTimeout = TimeSpan.FromSeconds(1);
    private static readonly byte[] ClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"u8.ToArray();

    private static WebApplication? s_application;
    private static IPEndPoint? s_endpoint;

    public static void Main(string[] args)
    {
        // WebApplication's default JSON providers otherwise allocate one inotify instance per
        // forked input. The campaign does not need configuration reloads, and disabling them keeps
        // startup deterministic without changing Kestrel's HTTP/2 protocol behavior.
        Environment.SetEnvironmentVariable("DOTNET_HOSTBUILDER__RELOADCONFIGONCHANGE", "false");

        if (args.Length != 0)
        {
            Replay(args);
            return;
        }

        Fuzzer.OutOfProcess.Run(stream =>
        {
            var decisions = ReadBoundedInput(stream);
            if (decisions is null || decisions.Length == 0)
            {
                return;
            }

            var scenario = StructuredHttp2Generator.Generate(decisions);
            StartServer();
            try
            {
                _ = Exercise(scenario, observeCoverage: true);
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
             !StringComparer.Ordinal.Equals(args[0], "--render")))
        {
            throw new ArgumentException("Usage: KestrelHttp2Fuzz --replay|--render INPUT");
        }

        var decisions = File.ReadAllBytes(args[1]);
        if (decisions.Length == 0 || decisions.Length > MaxDecisionLength)
        {
            throw new ArgumentOutOfRangeException(
                nameof(args),
                $"Replay input must contain between 1 and {MaxDecisionLength} bytes.");
        }

        var scenario = StructuredHttp2Generator.Generate(decisions);
        if (StringComparer.Ordinal.Equals(args[0], "--render"))
        {
            Console.Error.WriteLine(
                $"scenario={scenario.Id.ToString(CultureInfo.InvariantCulture)}:{scenario.Name} " +
                $"healthy={scenario.ExpectHealthy.ToString(CultureInfo.InvariantCulture).ToLowerInvariant()} " +
                $"transcript_bytes={scenario.Transcript.Length.ToString(CultureInfo.InvariantCulture)}");
            Console.WriteLine(Convert.ToBase64String(scenario.Transcript));
            return;
        }

        StartServer();
        try
        {
            var result = Exercise(scenario, observeCoverage: false);
            if (result.Contiguous.TimedOut || result.Segmented.TimedOut)
            {
                throw new TimeoutException(
                    $"Clean replay did not reach a terminal observation for {scenario.Name}. " +
                    $"contiguous={result.Contiguous.Describe()}; " +
                    $"segmented={result.Segmented.Describe()}");
            }
            Console.WriteLine(
                $"PASS scenario={scenario.Id.ToString(CultureInfo.InvariantCulture)}:{scenario.Name} " +
                $"healthy={scenario.ExpectHealthy.ToString(CultureInfo.InvariantCulture).ToLowerInvariant()} " +
                $"decision_sha256={Convert.ToHexString(SHA256.HashData(decisions))} " +
                $"transcript_bytes={scenario.Transcript.Length.ToString(CultureInfo.InvariantCulture)} " +
                $"transcript_sha256={Convert.ToHexString(SHA256.HashData(scenario.Transcript))}");
            Console.WriteLine($"contiguous={result.Contiguous.Describe()}");
            Console.WriteLine($"segmented={result.Segmented.Describe()}");
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
            options.Listen(
                IPAddress.Loopback,
                0,
                listenOptions => listenOptions.Protocols = HttpProtocols.Http2);
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
                $"The HTTP/2 harness loaded Kestrel from '{loadedAssembly}', expected '{expectedAssembly}'.");
        }

        var server = application.Services.GetRequiredService<IServer>();
        var addresses = server.Features.Get<IServerAddressesFeature>()?.Addresses;
        var address = addresses?.SingleOrDefault()
            ?? throw new InvalidOperationException("Kestrel did not publish exactly one HTTP/2 loopback address.");
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

        using var timeout = new CancellationTokenSource(ShutdownTimeout);
        try
        {
            application.StopAsync(timeout.Token).GetAwaiter().GetResult();
        }
        catch (OperationCanceledException) when (timeout.IsCancellationRequested)
        {
            // A deliberately incomplete stream may still be unwinding. Disposal below aborts only
            // this in-process loopback server and prevents the next fuzz input from inheriting it.
        }
        application.DisposeAsync().AsTask().GetAwaiter().GetResult();
    }

    private static async Task HandleRequestAsync(HttpContext context)
    {
        long bodyLength = 0;
        using var bodyHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

        while (true)
        {
            var read = await context.Request.BodyReader.ReadAsync(context.RequestAborted);
            bodyLength += read.Buffer.Length;
            foreach (var segment in read.Buffer)
            {
                bodyHash.AppendData(segment.Span);
            }
            context.Request.BodyReader.AdvanceTo(read.Buffer.End);
            if (read.IsCompleted)
            {
                break;
            }
        }

        var trailers = new StringBuilder();
        var trailerFeature = context.Features.Get<IHttpRequestTrailersFeature>();
        if (trailerFeature?.Available == true)
        {
            foreach (var trailer in trailerFeature.Trailers.OrderBy(
                pair => pair.Key,
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

        var streamId = context.Features.Get<IHttp2StreamIdFeature>()?.StreamId ?? -1;
        var responseText =
            $"stream={streamId.ToString(CultureInfo.InvariantCulture)};" +
            $"method={context.Request.Method};" +
            $"path={context.Request.Path.Value ?? String.Empty};" +
            $"body={bodyLength.ToString(CultureInfo.InvariantCulture)};" +
            $"bodysha={Convert.ToHexString(bodyHash.GetHashAndReset())};" +
            $"trailersha={Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(trailers.ToString())))};\n";
        var response = Encoding.UTF8.GetBytes(responseText);
        context.Response.StatusCode = StatusCodes.Status200OK;
        context.Response.ContentType = "text/plain";
        context.Response.ContentLength = response.Length;
        await context.Response.Body.WriteAsync(response, context.RequestAborted);
    }

    private static ExerciseResult Exercise(GeneratedScenario scenario, bool observeCoverage)
    {
        var endpoint = s_endpoint;
        if (s_application?.Lifetime.ApplicationStopping.IsCancellationRequested != false || endpoint is null)
        {
            throw new InvalidOperationException("The in-process HTTP/2 server stopped before the exchange.");
        }

        var contiguous = Exchange(endpoint, scenario, segmented: false);
        var segmented = Exchange(endpoint, scenario, segmented: true);

        AssertEquivalent(contiguous, segmented, scenario);
        if (scenario.ExpectHealthy)
        {
            AssertHealthy(contiguous, scenario, "contiguous");
            AssertHealthy(segmented, scenario, "segmented");
        }

        if (s_application.Lifetime.ApplicationStopping.IsCancellationRequested)
        {
            throw new InvalidOperationException("A single HTTP/2 exchange stopped the shared fuzz server.");
        }

        if (observeCoverage)
        {
            var fingerprint = Http2OutcomeCoverage.Observe(scenario.Id, contiguous, segmented);
            GC.KeepAlive(fingerprint);
        }

        return new ExerciseResult(contiguous, segmented);
    }

    private static void AssertEquivalent(
        Http2ExchangeOutcome contiguous,
        Http2ExchangeOutcome segmented,
        GeneratedScenario scenario)
    {
        // Partial observations are useful coverage but are not proof of a packetization
        // differential. Reserve the oracle for two complete terminal observations.
        if (!contiguous.IsComparable || !segmented.IsComparable)
        {
            return;
        }

        if (!StringComparer.Ordinal.Equals(contiguous.StableSignature, segmented.StableSignature))
        {
            throw new InvalidDataException(
                $"Kestrel HTTP/2 packetization divergence for {scenario.Name}. " +
                $"contiguous={contiguous.StableSignature}; segmented={segmented.StableSignature}");
        }
    }

    private static void AssertHealthy(
        Http2ExchangeOutcome outcome,
        GeneratedScenario scenario,
        string delivery)
    {
        if (outcome.TimedOut)
        {
            return;
        }

        if (outcome.GoAwayError is not null || outcome.ResetErrors.Count != 0 || !outcome.PingAck)
        {
            throw new InvalidDataException(
                $"Valid HTTP/2 scenario {scenario.Name} failed under {delivery}: {outcome.Describe()}");
        }

        foreach (var (streamId, marker) in scenario.ExpectedMarkers)
        {
            if (!outcome.ResponseData.TryGetValue(streamId, out var bytes) ||
                !Encoding.UTF8.GetString(bytes).Contains(marker, StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    $"Valid HTTP/2 scenario {scenario.Name} lost or crossed response stream " +
                    $"{streamId.ToString(CultureInfo.InvariantCulture)} under {delivery}. " +
                    $"Expected marker '{marker}', observed {outcome.Describe()}");
            }
        }
    }

    private static Http2ExchangeOutcome Exchange(
        IPEndPoint endpoint,
        GeneratedScenario scenario,
        bool segmented)
    {
        using var socket = ConnectAndHandshake(endpoint);
        var collector = new OutcomeCollector();
        var ping = StructuredHttp2Generator.CreatePingFrame();

        try
        {
            if (segmented)
            {
                SendSegmented(socket, scenario.Transcript);
                SendSegmented(socket, ping);
            }
            else
            {
                SendAll(socket, scenario.Transcript);
                SendAll(socket, ping);
            }
        }
        catch (SocketException ex) when (IsExpectedPeerClose(ex.SocketErrorCode))
        {
            collector.MarkEof();
        }
        catch (PeerClosedException)
        {
            collector.MarkEof();
        }

        var deadline = DateTime.UtcNow + ExchangeTimeout;
        while (DateTime.UtcNow < deadline)
        {
            var status = ReceiveFrame(socket, deadline, out var frame);
            if (status == ReceiveStatus.Timeout)
            {
                collector.MarkTimeout();
                break;
            }
            if (status == ReceiveStatus.Eof)
            {
                collector.MarkEof();
                break;
            }

            collector.Observe(frame!);
            if (collector.GoAwayError is not null)
            {
                break;
            }
            if (collector.PingAck && collector.HasCompleted(scenario.ExpectedMarkers.Keys))
            {
                DrainImmediatelyAvailable(socket, collector);
                break;
            }
        }

        return collector.Build();
    }

    private static Socket ConnectAndHandshake(IPEndPoint endpoint)
    {
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)
        {
            NoDelay = true,
            SendTimeout = (int)HandshakeTimeout.TotalMilliseconds,
            ReceiveTimeout = (int)HandshakeTimeout.TotalMilliseconds,
            LingerState = new LingerOption(enable: true, seconds: 0),
        };
        socket.Connect(endpoint);

        SendAll(socket, ClientPreface);
        SendAll(socket, BuildFrame(SettingsFrame, flags: 0, streamId: 0, payload: []));

        var deadline = DateTime.UtcNow + HandshakeTimeout;
        var receivedSettings = false;
        while (!receivedSettings)
        {
            var status = ReceiveFrame(socket, deadline, out var frame);
            if (status != ReceiveStatus.Frame)
            {
                socket.Dispose();
                throw new IOException($"Kestrel HTTP/2 handshake ended with {status} before SETTINGS.");
            }

            if (frame!.Type == SettingsFrame && (frame.Flags & Ack) == 0)
            {
                receivedSettings = true;
                SendAll(socket, BuildFrame(SettingsFrame, Ack, streamId: 0, payload: []));
            }
            else if (frame.Type == GoAwayFrame)
            {
                socket.Dispose();
                throw new IOException("Kestrel sent GOAWAY during an empty HTTP/2 handshake.");
            }
        }

        // Drain Kestrel's startup SETTINGS acknowledgement and initial connection WINDOW_UPDATE
        // before the generated transcript so accounting observations belong to this input.
        var drainDeadline = DateTime.UtcNow + TimeSpan.FromMilliseconds(20);
        while (DateTime.UtcNow < drainDeadline && socket.Poll(2_000, SelectMode.SelectRead))
        {
            var status = ReceiveFrame(socket, drainDeadline, out _);
            if (status != ReceiveStatus.Frame)
            {
                break;
            }
        }

        return socket;
    }

    private static void DrainImmediatelyAvailable(Socket socket, OutcomeCollector collector)
    {
        var deadline = DateTime.UtcNow + TimeSpan.FromMilliseconds(10);
        while (DateTime.UtcNow < deadline && socket.Poll(1_000, SelectMode.SelectRead))
        {
            var status = ReceiveFrame(socket, deadline, out var frame);
            if (status == ReceiveStatus.Frame)
            {
                collector.Observe(frame!);
            }
            else if (status == ReceiveStatus.Eof)
            {
                collector.MarkEof();
                break;
            }
            else
            {
                break;
            }
        }
    }

    private static void SendSegmented(Socket socket, byte[] bytes)
    {
        if (bytes.Length == 0)
        {
            return;
        }

        const int maxCuts = 128;
        var candidates = new SortedSet<int>();
        var cursor = 0;
        var frames = 0;
        while (cursor + 9 <= bytes.Length && frames < 32)
        {
            var payloadLength = (bytes[cursor] << 16) | (bytes[cursor + 1] << 8) | bytes[cursor + 2];
            var frameEnd = cursor + 9 + payloadLength;
            if (frameEnd > bytes.Length)
            {
                break;
            }

            candidates.Add(cursor + 1);
            candidates.Add(cursor + 3);
            candidates.Add(cursor + 8);
            candidates.Add(cursor + 9);
            if (payloadLength != 0)
            {
                candidates.Add(cursor + 10);
                candidates.Add(frameEnd - 1);
            }
            candidates.Add(frameEnd);
            cursor = frameEnd;
            frames++;
        }

        for (var i = 1; i < 33; i++)
        {
            candidates.Add((int)((long)bytes.Length * i / 33));
        }

        var selected = candidates
            .Where(value => value > 0 && value < bytes.Length)
            .Where((_, index) => candidates.Count <= maxCuts || index % Math.Max(1, candidates.Count / maxCuts) == 0)
            .Take(maxCuts)
            .ToArray();

        var offset = 0;
        foreach (var cut in selected)
        {
            SendAll(socket, bytes.AsSpan(offset, cut - offset));
            offset = cut;
        }
        SendAll(socket, bytes.AsSpan(offset));
    }

    private static void SendAll(Socket socket, ReadOnlySpan<byte> bytes)
    {
        while (!bytes.IsEmpty)
        {
            var sent = socket.Send(bytes, SocketFlags.None);
            if (sent == 0)
            {
                throw new PeerClosedException();
            }
            bytes = bytes[sent..];
        }
    }

    private static ReceiveStatus ReceiveFrame(
        Socket socket,
        DateTime deadline,
        out ReceivedFrame? frame)
    {
        frame = null;
        Span<byte> header = stackalloc byte[9];
        var status = ReceiveExact(socket, header, deadline);
        if (status != ReceiveStatus.Frame)
        {
            return status;
        }

        var payloadLength = (header[0] << 16) | (header[1] << 8) | header[2];
        if (payloadLength > MaxResponsePayloadLength)
        {
            throw new InvalidDataException(
                $"Kestrel emitted an oversized HTTP/2 frame ({payloadLength} bytes).");
        }

        var payload = new byte[payloadLength];
        if (payloadLength != 0)
        {
            status = ReceiveExact(socket, payload, deadline);
            if (status != ReceiveStatus.Frame)
            {
                throw new InvalidDataException(
                    $"Kestrel ended a response in the middle of a {payloadLength}-byte HTTP/2 frame.");
            }
        }

        frame = new ReceivedFrame(
            Type: header[3],
            Flags: header[4],
            StreamId: (int)(BinaryPrimitives.ReadUInt32BigEndian(header[5..]) & 0x7fff_ffffu),
            Payload: payload);
        return ReceiveStatus.Frame;
    }

    private static ReceiveStatus ReceiveExact(Socket socket, Span<byte> destination, DateTime deadline)
    {
        var offset = 0;
        while (offset < destination.Length)
        {
            var remaining = deadline - DateTime.UtcNow;
            if (remaining <= TimeSpan.Zero)
            {
                return offset == 0 ? ReceiveStatus.Timeout : throw new IOException("Timed out in a partial HTTP/2 frame.");
            }

            var microseconds = (int)Math.Clamp(remaining.TotalMilliseconds * 1000, 1, Int32.MaxValue);
            if (!socket.Poll(microseconds, SelectMode.SelectRead))
            {
                return offset == 0 ? ReceiveStatus.Timeout : throw new IOException("Timed out in a partial HTTP/2 frame.");
            }

            int received;
            try
            {
                received = socket.Receive(destination[offset..], SocketFlags.None);
            }
            catch (SocketException ex) when (IsExpectedPeerClose(ex.SocketErrorCode))
            {
                return offset == 0 ? ReceiveStatus.Eof : throw new IOException("Peer reset a partial HTTP/2 frame.", ex);
            }
            if (received == 0)
            {
                return offset == 0 ? ReceiveStatus.Eof : throw new IOException("Peer closed a partial HTTP/2 frame.");
            }
            offset += received;
        }

        return ReceiveStatus.Frame;
    }

    private static byte[] BuildFrame(byte type, byte flags, int streamId, ReadOnlySpan<byte> payload)
    {
        var result = new byte[9 + payload.Length];
        result[0] = (byte)(payload.Length >> 16);
        result[1] = (byte)(payload.Length >> 8);
        result[2] = (byte)payload.Length;
        result[3] = type;
        result[4] = flags;
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(5, 4), (uint)streamId & 0x7fff_ffffu);
        payload.CopyTo(result.AsSpan(9));
        return result;
    }

    private static byte[]? ReadBoundedInput(Stream stream)
    {
        using var input = new MemoryStream();
        var buffer = new byte[4096];
        while (true)
        {
            var read = stream.Read(buffer, 0, buffer.Length);
            if (read == 0)
            {
                return input.ToArray();
            }
            if (input.Length + read > MaxDecisionLength)
            {
                return null;
            }
            input.Write(buffer, 0, read);
        }
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

    private enum ReceiveStatus
    {
        Frame,
        Timeout,
        Eof,
    }

    private sealed record ReceivedFrame(byte Type, byte Flags, int StreamId, byte[] Payload);

    private sealed class PeerClosedException : IOException;

    private sealed class OutcomeCollector
    {
        private readonly Dictionary<int, MemoryStream> _data = [];
        private readonly HashSet<int> _completedStreams = [];
        private readonly Dictionary<int, uint> _resetErrors = [];
        private readonly Dictionary<int, long> _windowUpdates = [];
        private readonly Dictionary<byte, int> _frameCounts = [];
        private int _frameCount;
        private int _accumulatedData;

        public bool PingAck { get; private set; }
        public uint? GoAwayError { get; private set; }
        public int? GoAwayLastStream { get; private set; }
        public bool TimedOut { get; private set; }
        public bool Eof { get; private set; }

        public void Observe(ReceivedFrame frame)
        {
            _frameCount++;
            _frameCounts.TryGetValue(frame.Type, out var count);
            _frameCounts[frame.Type] = count + 1;

            switch (frame.Type)
            {
                case DataFrame:
                    ObserveData(frame);
                    break;
                case HeadersFrame:
                    if ((frame.Flags & EndStream) != 0)
                    {
                        _completedStreams.Add(frame.StreamId);
                    }
                    break;
                case RstStreamFrame when frame.Payload.Length == 4:
                    _resetErrors[frame.StreamId] = BinaryPrimitives.ReadUInt32BigEndian(frame.Payload);
                    _completedStreams.Add(frame.StreamId);
                    break;
                case PingFrame when (frame.Flags & Ack) != 0:
                    PingAck = frame.Payload.AsSpan().SequenceEqual(StructuredHttp2Generator.PingPayload);
                    break;
                case GoAwayFrame when frame.Payload.Length >= 8:
                    GoAwayLastStream = (int)(BinaryPrimitives.ReadUInt32BigEndian(frame.Payload) & 0x7fff_ffffu);
                    GoAwayError = BinaryPrimitives.ReadUInt32BigEndian(frame.Payload.AsSpan(4));
                    break;
                case WindowUpdateFrame when frame.Payload.Length == 4:
                    var increment = BinaryPrimitives.ReadUInt32BigEndian(frame.Payload) & 0x7fff_ffffu;
                    _windowUpdates.TryGetValue(frame.StreamId, out var total);
                    _windowUpdates[frame.StreamId] = total + increment;
                    break;
            }
        }

        public bool HasCompleted(IEnumerable<int> expectedStreams) =>
            expectedStreams.All(streamId => _completedStreams.Contains(streamId));

        public void MarkTimeout() => TimedOut = true;

        public void MarkEof() => Eof = true;

        public Http2ExchangeOutcome Build()
        {
            var responseData = _data.ToDictionary(
                pair => pair.Key,
                pair => pair.Value.ToArray());
            foreach (var stream in _data.Values)
            {
                stream.Dispose();
            }

            var resetErrors = new Dictionary<int, uint>(_resetErrors);
            var windowUpdates = new Dictionary<int, long>(_windowUpdates);
            var frameCounts = new Dictionary<byte, int>(_frameCounts);
            var stable = BuildStableSignature(responseData, resetErrors);
            return new Http2ExchangeOutcome(
                PingAck,
                GoAwayError,
                GoAwayLastStream,
                TimedOut,
                Eof,
                _frameCount,
                responseData,
                resetErrors,
                windowUpdates,
                frameCounts,
                stable);
        }

        private void ObserveData(ReceivedFrame frame)
        {
            ReadOnlySpan<byte> data = frame.Payload;
            if ((frame.Flags & Padded) != 0)
            {
                if (data.Length == 0)
                {
                    throw new InvalidDataException("Kestrel emitted a padded DATA frame without a pad length.");
                }
                var paddingLength = data[0];
                if (paddingLength >= data.Length)
                {
                    throw new InvalidDataException("Kestrel emitted invalid response DATA padding.");
                }
                data = data.Slice(1, data.Length - paddingLength - 1);
            }

            if (_accumulatedData + data.Length > MaxAccumulatedResponseData)
            {
                throw new InvalidDataException("Kestrel emitted too much response DATA for the bounded harness.");
            }
            _accumulatedData += data.Length;

            if (!_data.TryGetValue(frame.StreamId, out var output))
            {
                output = new MemoryStream();
                _data.Add(frame.StreamId, output);
            }
            output.Write(data);
            if ((frame.Flags & EndStream) != 0)
            {
                _completedStreams.Add(frame.StreamId);
            }
        }

        private string BuildStableSignature(
            Dictionary<int, byte[]> responseData,
            Dictionary<int, uint> resetErrors)
        {
            var signature = new StringBuilder();
            if (GoAwayError is not null)
            {
                signature.Append("goaway:")
                    .Append(GoAwayLastStream.GetValueOrDefault().ToString(CultureInfo.InvariantCulture))
                    .Append(':')
                    .Append(GoAwayError.Value.ToString(CultureInfo.InvariantCulture));
            }
            else if (PingAck)
            {
                signature.Append("ping");
            }
            else if (Eof)
            {
                signature.Append("eof");
            }
            else
            {
                signature.Append("open");
            }

            foreach (var (streamId, error) in resetErrors.OrderBy(pair => pair.Key))
            {
                signature.Append(";rst:")
                    .Append(streamId.ToString(CultureInfo.InvariantCulture))
                    .Append(':')
                    .Append(error.ToString(CultureInfo.InvariantCulture));
            }
            foreach (var (streamId, bytes) in responseData.OrderBy(pair => pair.Key))
            {
                signature.Append(";data:")
                    .Append(streamId.ToString(CultureInfo.InvariantCulture))
                    .Append(':')
                    .Append(bytes.Length.ToString(CultureInfo.InvariantCulture))
                    .Append(':')
                    .Append(Convert.ToHexString(SHA256.HashData(bytes)));
            }
            return signature.ToString();
        }
    }

    private sealed record ExerciseResult(
        Http2ExchangeOutcome Contiguous,
        Http2ExchangeOutcome Segmented);
}

internal sealed record Http2ExchangeOutcome(
    bool PingAck,
    uint? GoAwayError,
    int? GoAwayLastStream,
    bool TimedOut,
    bool Eof,
    int FrameCount,
    Dictionary<int, byte[]> ResponseData,
    Dictionary<int, uint> ResetErrors,
    Dictionary<int, long> WindowUpdates,
    Dictionary<byte, int> FrameCounts,
    string StableSignature)
{
    public bool IsComparable => !TimedOut && (PingAck || GoAwayError is not null || Eof);

    public string Describe()
    {
        var data = String.Join(
            ',',
            ResponseData.OrderBy(pair => pair.Key).Select(pair =>
                $"{pair.Key.ToString(CultureInfo.InvariantCulture)}:{pair.Value.Length.ToString(CultureInfo.InvariantCulture)}:" +
                Convert.ToHexString(SHA256.HashData(pair.Value))));
        var resets = String.Join(
            ',',
            ResetErrors.OrderBy(pair => pair.Key).Select(pair =>
                $"{pair.Key.ToString(CultureInfo.InvariantCulture)}:{pair.Value.ToString(CultureInfo.InvariantCulture)}"));
        var windows = String.Join(
            ',',
            WindowUpdates.OrderBy(pair => pair.Key).Select(pair =>
                $"{pair.Key.ToString(CultureInfo.InvariantCulture)}:{pair.Value.ToString(CultureInfo.InvariantCulture)}"));
        return
            $"ping={PingAck.ToString(CultureInfo.InvariantCulture).ToLowerInvariant()} " +
            $"goaway={GoAwayError?.ToString(CultureInfo.InvariantCulture) ?? "none"} " +
            $"last={GoAwayLastStream?.ToString(CultureInfo.InvariantCulture) ?? "none"} " +
            $"timeout={TimedOut.ToString(CultureInfo.InvariantCulture).ToLowerInvariant()} " +
            $"eof={Eof.ToString(CultureInfo.InvariantCulture).ToLowerInvariant()} " +
            $"frames={FrameCount.ToString(CultureInfo.InvariantCulture)} " +
            $"resets=[{resets}] windows=[{windows}] data=[{data}]";
    }
}

/// <summary>
/// The only SharpFuzz-instrumented type. It converts asynchronous protocol outcomes into stable
/// coverage classes while leaving the source-built Kestrel product assembly pristine.
/// </summary>
internal static class Http2OutcomeCoverage
{
    [MethodImpl(MethodImplOptions.NoInlining)]
    public static int Observe(
        int scenario,
        Http2ExchangeOutcome contiguous,
        Http2ExchangeOutcome segmented)
    {
        var fingerprint = Mix(17, scenario);
        fingerprint = Mix(fingerprint, ClassifyTerminal(contiguous));
        fingerprint = Mix(fingerprint, ClassifyTerminal(segmented));
        fingerprint = Mix(fingerprint, Bucket(contiguous.FrameCount));
        fingerprint = Mix(fingerprint, Bucket(segmented.FrameCount));
        fingerprint = Mix(fingerprint, Bucket(contiguous.ResponseData.Count));
        fingerprint = Mix(fingerprint, Bucket(segmented.ResponseData.Count));
        fingerprint = Mix(fingerprint, Bucket(contiguous.ResetErrors.Count));
        fingerprint = Mix(fingerprint, Bucket(segmented.ResetErrors.Count));
        fingerprint = Mix(fingerprint, Bucket(contiguous.WindowUpdates.Count));
        fingerprint = Mix(fingerprint, Bucket(segmented.WindowUpdates.Count));
        fingerprint = Mix(
            fingerprint,
            StringComparer.Ordinal.Equals(contiguous.StableSignature, segmented.StableSignature) ? 307 : 311);
        return fingerprint;
    }

    private static int ClassifyTerminal(Http2ExchangeOutcome outcome)
    {
        if (outcome.TimedOut)
        {
            return 101;
        }
        if (outcome.GoAwayError is not null)
        {
            return outcome.GoAwayError.Value switch
            {
                0 => 103,
                1 => 107,
                2 => 109,
                3 => 113,
                6 => 127,
                _ => 131,
            };
        }
        if (outcome.PingAck)
        {
            return 137;
        }
        if (outcome.Eof)
        {
            return 139;
        }
        return 149;
    }

    private static int Bucket(int value) => value switch
    {
        0 => 151,
        1 => 157,
        2 => 163,
        <= 4 => 167,
        <= 16 => 173,
        <= 64 => 179,
        _ => 181,
    };

    private static int Mix(int current, int value) => unchecked((current * 397) ^ value);
}
