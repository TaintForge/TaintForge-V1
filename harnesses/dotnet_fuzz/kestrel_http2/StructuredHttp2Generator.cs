using System.Buffers.Binary;
using System.Globalization;
using System.Text;

namespace KestrelHttp2Fuzz;

internal sealed record GeneratedScenario(
    int Id,
    string Name,
    byte[] Transcript,
    bool ExpectHealthy,
    Dictionary<int, string> ExpectedMarkers);

/// <summary>
/// Maps bounded fuzzer decisions onto HTTP/2 frame sequences. Each scenario keeps unrelated
/// protocol grammar valid while varying one framing, stream-lifecycle, or flow-control invariant.
/// </summary>
internal static class StructuredHttp2Generator
{
    internal const int ScenarioCount = 29;
    internal const int VictimStreamId = 7;
    internal static readonly byte[] PingPayload = "TFH2PING"u8.ToArray();

    private const byte Data = 0x0;
    private const byte Headers = 0x1;
    private const byte RstStream = 0x3;
    private const byte Settings = 0x4;
    private const byte Ping = 0x6;
    private const byte WindowUpdate = 0x8;
    private const byte Continuation = 0x9;

    private const byte EndStream = 0x1;
    private const byte Ack = 0x1;
    private const byte EndHeaders = 0x4;
    private const byte Padded = 0x8;
    private const byte Priority = 0x20;

    private const int MaxGeneratedTranscriptLength = 768 * 1024;

    private static readonly int[] BodyLengths =
    [
        0, 1, 2, 3, 7, 8, 15, 16, 31, 32, 63, 64, 255, 256,
        1023, 2047, 2048, 2049, 4095, 4096, 4097, 8191, 8192,
        8193, 16383, 16384, 16385, 32767, 32768,
    ];

    private static readonly int[] PaddingBurstCounts = [1, 2, 16, 255, 256, 1536, 1537];
    private static readonly int[] PaddingLengths = [0, 1, 15, 255];

    public static GeneratedScenario Generate(byte[] decisions)
    {
        ArgumentNullException.ThrowIfNull(decisions);
        if (decisions.Length == 0)
        {
            throw new ArgumentException("HTTP/2 semantic generation needs at least one decision byte.", nameof(decisions));
        }

        var cursor = new DecisionCursor(decisions);
        var scenarioId = cursor.Next() % ScenarioCount;
        using var transcript = new MemoryStream(capacity: 4096);
        var expected = new Dictionary<int, string>();
        var expectHealthy = false;
        var name = ScenarioName(scenarioId);

        switch (scenarioId)
        {
            case 0:
                WriteCompleteRequest(transcript, 1, "GET", "/single", body: []);
                AddExpected(expected, 1, "GET", "/single", 0);
                expectHealthy = true;
                break;
            case 1:
            {
                var block = EncodeRequestHeaders("GET", "/continuation", contentLength: null);
                var split = 1 + cursor.Next() % (block.Length - 1);
                WriteSplitHeaders(transcript, 1, block, endStream: true, split: split);
                AddExpected(expected, 1, "GET", "/continuation", 0);
                expectHealthy = true;
                break;
            }
            case 2:
            {
                var block = EncodeRequestHeaders("GET", "/empty-continuation", contentLength: null);
                WriteHeaders(transcript, 1, block, endStream: true, endHeaders: false);
                WriteFrame(transcript, Continuation, EndHeaders, 1, []);
                AddExpected(expected, 1, "GET", "/empty-continuation", 0);
                expectHealthy = true;
                break;
            }
            case 3:
            {
                var paddingLength = cursor.Next() % 16;
                var block = EncodeRequestHeaders("GET", "/padded-headers", contentLength: null);
                WriteHeaders(
                    transcript,
                    1,
                    block,
                    endStream: true,
                    endHeaders: true,
                    padded: true,
                    paddingLength: paddingLength);
                AddExpected(expected, 1, "GET", "/padded-headers", 0);
                expectHealthy = true;
                break;
            }
            case 4:
            {
                var block = EncodeRequestHeaders("GET", "/priority-headers", contentLength: null);
                WriteHeaders(
                    transcript,
                    1,
                    block,
                    endStream: true,
                    endHeaders: true,
                    priority: true,
                    dependency: 0,
                    weight: cursor.Next());
                AddExpected(expected, 1, "GET", "/priority-headers", 0);
                expectHealthy = true;
                break;
            }
            case 5:
            {
                var block = EncodeRequestHeaders("GET", "/padded-priority", contentLength: null);
                WriteHeaders(
                    transcript,
                    1,
                    block,
                    endStream: true,
                    endHeaders: true,
                    padded: true,
                    paddingLength: cursor.Next() % 16,
                    priority: true,
                    dependency: 0,
                    weight: cursor.Next());
                AddExpected(expected, 1, "GET", "/padded-priority", 0);
                expectHealthy = true;
                break;
            }
            case 6:
                // A one-byte payload declares one byte of padding. The pad-length byte itself
                // leaves no room for that padding, so Kestrel must reject the frame.
                WriteFrame(transcript, Headers, EndStream | EndHeaders | Padded, 1, [1]);
                break;
            case 7:
                // Source boundary at Http2Connection.ProcessHeadersFrameAsync: PADDED+PRIORITY,
                // payload length 6, and pad length 1 yields HeadersPayloadLength == -1.
                WriteFrame(
                    transcript,
                    Headers,
                    EndStream | EndHeaders | Padded | Priority,
                    1,
                    [1, 0, 0, 0, 0, 0]);
                break;
            case 8:
                WriteFrame(transcript, Continuation, EndHeaders, 1, EncodeRequestHeaders("GET", "/orphan", null));
                break;
            case 9:
            {
                var block = EncodeRequestHeaders("GET", "/wrong-stream", null);
                var split = Math.Max(1, block.Length / 2);
                WriteHeaders(transcript, 1, block.AsSpan(0, split), endStream: true, endHeaders: false);
                WriteFrame(transcript, Continuation, EndHeaders, 3, block.AsSpan(split));
                break;
            }
            case 10:
            {
                var block = EncodeRequestHeaders("POST", "/interleaved", contentLength: 1);
                WriteHeaders(transcript, 1, block.AsSpan(0, 1), endStream: false, endHeaders: false);
                WriteData(transcript, 1, [cursor.Next()], endStream: true);
                break;
            }
            case 11:
            {
                var body = MakeBody(cursor, Pick(cursor, BodyLengths));
                WriteBodyRequest(transcript, 1, "/data-boundaries", body, cursor.Next());
                AddExpected(expected, 1, "POST", "/data-boundaries", body.Length);
                expectHealthy = true;
                break;
            }
            case 12:
            {
                var body = MakeBody(cursor, 1 + cursor.Next() % 64);
                WriteHeaders(
                    transcript,
                    1,
                    EncodeRequestHeaders("POST", "/data-pad-zero", body.Length),
                    endStream: false,
                    endHeaders: true);
                WriteData(transcript, 1, body, endStream: true, padded: true, paddingLength: 0);
                AddExpected(expected, 1, "POST", "/data-pad-zero", body.Length);
                expectHealthy = true;
                break;
            }
            case 13:
            {
                var body = MakeBody(cursor, cursor.Next() % 33);
                WriteHeaders(
                    transcript,
                    1,
                    EncodeRequestHeaders("POST", "/data-pad-max", body.Length),
                    endStream: false,
                    endHeaders: true);
                WriteData(transcript, 1, body, endStream: true, padded: true, paddingLength: 255);
                AddExpected(expected, 1, "POST", "/data-pad-max", body.Length);
                expectHealthy = true;
                break;
            }
            case 14:
                WriteHeaders(
                    transcript,
                    1,
                    EncodeRequestHeaders("POST", "/invalid-data-padding", 0),
                    endStream: false,
                    endHeaders: true);
                WriteFrame(transcript, Data, EndStream | Padded, 1, [1]);
                break;
            case 15:
            {
                var body = MakeBody(cursor, cursor.Next() % 65);
                WriteHeaders(
                    transcript,
                    1,
                    EncodeRequestHeaders("POST", "/trailers", body.Length),
                    endStream: false,
                    endHeaders: true);
                WriteData(transcript, 1, body, endStream: false);
                WriteHeaders(
                    transcript,
                    1,
                    EncodeTrailers("x-tf-trailer", "single"),
                    endStream: true,
                    endHeaders: true);
                AddExpected(expected, 1, "POST", "/trailers", body.Length);
                expectHealthy = true;
                break;
            }
            case 16:
            {
                var body = MakeBody(cursor, cursor.Next() % 65);
                WriteHeaders(
                    transcript,
                    1,
                    EncodeRequestHeaders("POST", "/trailer-continuation", body.Length),
                    endStream: false,
                    endHeaders: true);
                WriteData(transcript, 1, body, endStream: false);
                var trailers = EncodeTrailers("x-tf-trailer", "continued");
                var split = 1 + cursor.Next() % (trailers.Length - 1);
                WriteHeaders(transcript, 1, trailers.AsSpan(0, split), endStream: true, endHeaders: false);
                WriteFrame(transcript, Continuation, EndHeaders, 1, trailers.AsSpan(split));
                AddExpected(expected, 1, "POST", "/trailer-continuation", body.Length);
                expectHealthy = true;
                break;
            }
            case 17:
                WriteHeaders(
                    transcript,
                    1,
                    EncodeRequestHeaders("POST", "/trailers-no-end", 0),
                    endStream: false,
                    endHeaders: true);
                WriteHeaders(
                    transcript,
                    1,
                    EncodeTrailers("x-tf-trailer", "missing-end-stream"),
                    endStream: false,
                    endHeaders: true);
                break;
            case 18:
                WriteCompleteRequest(transcript, 1, "GET", "/closed", body: []);
                WriteData(transcript, 1, [cursor.Next()], endStream: true);
                break;
            case 19:
                WriteHeaders(
                    transcript,
                    1,
                    EncodeRequestHeaders("POST", "/reset", contentLength: null),
                    endStream: false,
                    endHeaders: true);
                WriteUInt32Frame(transcript, RstStream, flags: 0, streamId: 1, value: 0);
                WriteData(transcript, 1, [cursor.Next()], endStream: true);
                break;
            case 20:
                WriteHeaders(
                    transcript,
                    2,
                    EncodeRequestHeaders("GET", "/even-stream", null),
                    endStream: true,
                    endHeaders: true);
                break;
            case 21:
                WriteUInt32Frame(transcript, WindowUpdate, flags: 0, streamId: 0, value: 0);
                break;
            case 22:
                WriteHeaders(
                    transcript,
                    1,
                    EncodeRequestHeaders("POST", "/zero-window", null),
                    endStream: false,
                    endHeaders: true);
                WriteUInt32Frame(transcript, WindowUpdate, flags: 0, streamId: 1, value: 0);
                break;
            case 23:
            {
                var body = MakeBody(cursor, 1 + cursor.Next() % 256);
                WriteCompleteRequest(transcript, 1, "POST", "/multi-a", body);
                WriteCompleteRequest(transcript, 3, "GET", "/multi-b", body: []);
                AddExpected(expected, 1, "POST", "/multi-a", body.Length);
                AddExpected(expected, 3, "GET", "/multi-b", 0);
                expectHealthy = true;
                break;
            }
            case 24:
            {
                var frameCount = Pick(cursor, PaddingBurstCounts);
                var paddingLength = Pick(cursor, PaddingLengths);
                WriteHeaders(
                    transcript,
                    1,
                    EncodeRequestHeaders("POST", "/padding-burst", 0),
                    endStream: false,
                    endHeaders: true);
                for (var i = 0; i < frameCount; i++)
                {
                    WriteData(
                        transcript,
                        1,
                        [],
                        endStream: false,
                        padded: true,
                        paddingLength: paddingLength);
                }
                WriteData(transcript, 1, [], endStream: true);
                AddExpected(expected, 1, "POST", "/padding-burst", 0);
                expectHealthy = true;
                break;
            }
            case 25:
            {
                uint[] windowSizes = [0, 1, 65_535, Int32.MaxValue, 0x8000_0000u];
                var windowSize = windowSizes[cursor.Next() % windowSizes.Length];
                WriteSetting(transcript, settingId: 4, value: windowSize);
                WriteCompleteRequest(transcript, 1, "GET", "/settings-window", body: []);
                if (windowSize is 65_535 or Int32.MaxValue)
                {
                    AddExpected(expected, 1, "GET", "/settings-window", 0);
                    expectHealthy = true;
                }
                break;
            }
            case 26:
                WriteCompleteRequest(transcript, 1, "GET", "/stream-once", body: []);
                WriteCompleteRequest(transcript, 1, "GET", "/stream-reused", body: []);
                break;
            case 27:
                WriteCompleteRequest(transcript, 3, "GET", "/higher-first", body: []);
                WriteCompleteRequest(transcript, 1, "GET", "/lower-late", body: []);
                break;
            case 28:
            {
                var paddingFrames = 1 + cursor.Next() % 32;
                var paddingLength = Pick(cursor, PaddingLengths);
                var firstBody = MakeBody(cursor, 1 + cursor.Next() % 4096);
                var secondBody = MakeBody(cursor, 1 + cursor.Next() % 4096);
                WriteHeaders(
                    transcript,
                    1,
                    EncodeRequestHeaders("POST", "/flow-a", firstBody.Length),
                    endStream: false,
                    endHeaders: true);
                for (var i = 0; i < paddingFrames; i++)
                {
                    WriteData(
                        transcript,
                        1,
                        [],
                        endStream: false,
                        padded: true,
                        paddingLength: paddingLength);
                }
                WriteData(transcript, 1, firstBody, endStream: true);
                WriteCompleteRequest(transcript, 3, "POST", "/flow-b", secondBody);
                AddExpected(expected, 1, "POST", "/flow-a", firstBody.Length);
                AddExpected(expected, 3, "POST", "/flow-b", secondBody.Length);
                expectHealthy = true;
                break;
            }
        }

        WriteCompleteRequest(transcript, VictimStreamId, "GET", "/victim", body: []);
        if (expectHealthy)
        {
            AddExpected(expected, VictimStreamId, "GET", "/victim", 0);
        }

        if (transcript.Length > MaxGeneratedTranscriptLength)
        {
            throw new InvalidOperationException(
                $"Generated HTTP/2 transcript exceeded {MaxGeneratedTranscriptLength} bytes.");
        }

        return new GeneratedScenario(scenarioId, name, transcript.ToArray(), expectHealthy, expected);
    }

    public static byte[] CreatePingFrame()
    {
        using var frame = new MemoryStream(capacity: 17);
        WriteFrame(frame, Ping, flags: 0, streamId: 0, PingPayload);
        return frame.ToArray();
    }

    private static string ScenarioName(int id) => id switch
    {
        0 => "valid-single",
        1 => "valid-continuation",
        2 => "valid-empty-continuation",
        3 => "valid-padded-headers",
        4 => "valid-priority-headers",
        5 => "valid-padded-priority-headers",
        6 => "invalid-headers-padding",
        7 => "headers-padding-priority-negative-fragment",
        8 => "continuation-without-headers",
        9 => "continuation-wrong-stream",
        10 => "data-interleaved-with-headers",
        11 => "data-frame-boundaries",
        12 => "data-padding-zero",
        13 => "data-padding-max",
        14 => "invalid-data-padding",
        15 => "trailers-single",
        16 => "trailers-continuation",
        17 => "trailers-without-end-stream",
        18 => "data-after-end-stream",
        19 => "data-after-reset",
        20 => "even-stream-id",
        21 => "connection-window-update-zero",
        22 => "stream-window-update-zero",
        23 => "multi-stream-pipeline",
        24 => "padded-data-flow-burst",
        25 => "settings-initial-window-boundary",
        26 => "stream-id-reuse",
        27 => "lower-stream-after-higher",
        28 => "cross-stream-padding-and-data",
        _ => throw new ArgumentOutOfRangeException(nameof(id)),
    };

    private static void AddExpected(
        Dictionary<int, string> expected,
        int streamId,
        string method,
        string path,
        int bodyLength)
    {
        expected.Add(
            streamId,
            $"stream={streamId.ToString(CultureInfo.InvariantCulture)};" +
            $"method={method};path={path};body={bodyLength.ToString(CultureInfo.InvariantCulture)};");
    }

    private static int Pick(DecisionCursor cursor, int[] values) => values[cursor.Next() % values.Length];

    private static byte[] MakeBody(DecisionCursor cursor, int length)
    {
        var body = new byte[length];
        for (var i = 0; i < body.Length; i++)
        {
            body[i] = cursor.Next();
        }
        return body;
    }

    private static void WriteCompleteRequest(
        Stream output,
        int streamId,
        string method,
        string path,
        byte[] body)
    {
        WriteHeaders(
            output,
            streamId,
            EncodeRequestHeaders(method, path, body.Length == 0 ? null : body.Length),
            endStream: body.Length == 0,
            endHeaders: true);
        if (body.Length != 0)
        {
            WriteData(output, streamId, body, endStream: true);
        }
    }

    private static void WriteBodyRequest(
        Stream output,
        int streamId,
        string path,
        byte[] body,
        byte splitSelector)
    {
        WriteHeaders(
            output,
            streamId,
            EncodeRequestHeaders("POST", path, body.Length),
            endStream: false,
            endHeaders: true);

        if (body.Length == 0)
        {
            WriteData(output, streamId, [], endStream: true);
            return;
        }

        int[] frameSizes = [1, 7, 1024, 16_383, 16_384];
        var preferred = frameSizes[splitSelector % frameSizes.Length];
        var offset = 0;
        while (offset < body.Length)
        {
            var length = Math.Min(preferred, body.Length - offset);
            var endStream = offset + length == body.Length;
            WriteData(output, streamId, body.AsSpan(offset, length), endStream);
            offset += length;
        }
    }

    private static void WriteSplitHeaders(
        Stream output,
        int streamId,
        byte[] block,
        bool endStream,
        int split)
    {
        WriteHeaders(output, streamId, block.AsSpan(0, split), endStream, endHeaders: false);
        WriteFrame(output, Continuation, EndHeaders, streamId, block.AsSpan(split));
    }

    private static void WriteHeaders(
        Stream output,
        int streamId,
        ReadOnlySpan<byte> headerBlock,
        bool endStream,
        bool endHeaders,
        bool padded = false,
        int paddingLength = 0,
        bool priority = false,
        int dependency = 0,
        byte weight = 16)
    {
        using var payload = new MemoryStream(capacity: headerBlock.Length + paddingLength + 6);
        var flags = (byte)0;
        if (endStream)
        {
            flags |= EndStream;
        }
        if (endHeaders)
        {
            flags |= EndHeaders;
        }
        if (padded)
        {
            flags |= Padded;
            payload.WriteByte((byte)paddingLength);
        }
        if (priority)
        {
            flags |= Priority;
            Span<byte> priorityBytes = stackalloc byte[5];
            BinaryPrimitives.WriteUInt32BigEndian(priorityBytes, (uint)dependency & 0x7fff_ffffu);
            priorityBytes[4] = weight;
            payload.Write(priorityBytes);
        }

        payload.Write(headerBlock);
        if (paddingLength != 0)
        {
            payload.Write(new byte[paddingLength]);
        }

        WriteFrame(output, Headers, flags, streamId, payload.ToArray());
    }

    private static void WriteData(
        Stream output,
        int streamId,
        ReadOnlySpan<byte> data,
        bool endStream,
        bool padded = false,
        int paddingLength = 0)
    {
        using var payload = new MemoryStream(capacity: data.Length + paddingLength + 1);
        var flags = endStream ? EndStream : (byte)0;
        if (padded)
        {
            flags |= Padded;
            payload.WriteByte((byte)paddingLength);
        }
        payload.Write(data);
        if (paddingLength != 0)
        {
            payload.Write(new byte[paddingLength]);
        }
        WriteFrame(output, Data, flags, streamId, payload.ToArray());
    }

    private static void WriteSetting(Stream output, ushort settingId, uint value)
    {
        Span<byte> payload = stackalloc byte[6];
        BinaryPrimitives.WriteUInt16BigEndian(payload, settingId);
        BinaryPrimitives.WriteUInt32BigEndian(payload[2..], value);
        WriteFrame(output, Settings, flags: 0, streamId: 0, payload);
    }

    private static void WriteUInt32Frame(Stream output, byte type, byte flags, int streamId, uint value)
    {
        Span<byte> payload = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(payload, value);
        WriteFrame(output, type, flags, streamId, payload);
    }

    private static void WriteFrame(
        Stream output,
        byte type,
        byte flags,
        int streamId,
        ReadOnlySpan<byte> payload)
    {
        if (payload.Length > 0x00ff_ffff)
        {
            throw new ArgumentOutOfRangeException(nameof(payload));
        }

        Span<byte> header = stackalloc byte[9];
        header[0] = (byte)(payload.Length >> 16);
        header[1] = (byte)(payload.Length >> 8);
        header[2] = (byte)payload.Length;
        header[3] = type;
        header[4] = flags;
        BinaryPrimitives.WriteUInt32BigEndian(header[5..], (uint)streamId & 0x7fff_ffffu);
        output.Write(header);
        output.Write(payload);
    }

    private static byte[] EncodeRequestHeaders(string method, string path, int? contentLength)
    {
        using var block = new MemoryStream(capacity: 128);
        switch (method)
        {
            case "GET":
                block.WriteByte(0x82); // Indexed :method GET.
                break;
            case "POST":
                block.WriteByte(0x83); // Indexed :method POST.
                break;
            default:
                WriteLiteral(block, ":method", method);
                break;
        }

        block.WriteByte(0x86); // Indexed :scheme http.
        if (path == "/")
        {
            block.WriteByte(0x84); // Indexed :path /.
        }
        else
        {
            WriteLiteralWithIndexedName(block, nameIndex: 4, path);
        }
        WriteLiteralWithIndexedName(block, nameIndex: 1, "localhost");

        if (contentLength.HasValue)
        {
            WriteLiteral(
                block,
                "content-length",
                contentLength.Value.ToString(CultureInfo.InvariantCulture));
        }

        return block.ToArray();
    }

    private static byte[] EncodeTrailers(string name, string value)
    {
        using var block = new MemoryStream(capacity: name.Length + value.Length + 4);
        WriteLiteral(block, name, value);
        return block.ToArray();
    }

    private static void WriteLiteral(Stream output, string name, string value)
    {
        output.WriteByte(0x00); // Literal header field without indexing, new name.
        WriteString(output, name);
        WriteString(output, value);
    }

    private static void WriteLiteralWithIndexedName(Stream output, int nameIndex, string value)
    {
        WriteInteger(output, nameIndex, prefixBits: 4, firstByte: 0x00);
        WriteString(output, value);
    }

    private static void WriteString(Stream output, string value)
    {
        var bytes = Encoding.ASCII.GetBytes(value);
        WriteInteger(output, bytes.Length, prefixBits: 7, firstByte: 0x00);
        output.Write(bytes);
    }

    private static void WriteInteger(Stream output, int value, int prefixBits, byte firstByte)
    {
        var prefixMax = (1 << prefixBits) - 1;
        if (value < prefixMax)
        {
            output.WriteByte((byte)(firstByte | value));
            return;
        }

        output.WriteByte((byte)(firstByte | prefixMax));
        value -= prefixMax;
        while (value >= 128)
        {
            output.WriteByte((byte)((value & 0x7f) | 0x80));
            value >>= 7;
        }
        output.WriteByte((byte)value);
    }

    private sealed class DecisionCursor
    {
        private readonly byte[] _decisions;
        private int _offset;
        private uint _state = 2166136261;

        public DecisionCursor(byte[] decisions)
        {
            _decisions = decisions;
            foreach (var value in decisions)
            {
                _state = (_state ^ value) * 16777619;
            }
        }

        public byte Next()
        {
            if (_offset < _decisions.Length)
            {
                return _decisions[_offset++];
            }

            _state ^= _state << 13;
            _state ^= _state >> 17;
            _state ^= _state << 5;
            return (byte)_state;
        }
    }
}
