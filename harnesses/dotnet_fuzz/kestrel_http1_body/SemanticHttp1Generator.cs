using System.Globalization;
using System.Text;

namespace KestrelHttp1BodyFuzz;

/// <summary>
/// Maps arbitrary fuzzer bytes onto an HTTP/1 transcript whose unrelated grammar remains valid.
/// The first nine bytes select framing, chunk, pipeline, a source-derived body-size boundary,
/// split, header, method, path, and application-consumption modes. Remaining bytes become bounded
/// body data. Each malformed mode damages one framing invariant while retaining the surrounding
/// request and fixed victim request used by Program.
/// </summary>
internal static class SemanticHttp1Generator
{
    // Kestrel's socket transport requests at least 2 KiB at a time and its pinned memory pool
    // uses 4 KiB blocks. Exercise both sides of those boundaries, plus subsequent pooled-buffer
    // crossings, without letting one generated transcript exceed the harness's 64 KiB input cap.
    private static readonly int[] SemanticBodyLengths =
    [
        0, 1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256,
        511, 512, 1023, 1024, 2047, 2048, 2049, 4095, 4096, 4097, 8191, 8192,
        8193, 16383, 16384, 16385,
    ];

    public static byte[] Generate(byte[] decisions)
    {
        ArgumentNullException.ThrowIfNull(decisions);
        if (decisions.Length == 0)
        {
            throw new ArgumentException("Semantic generation requires at least one decision byte.", nameof(decisions));
        }

        var cursor = new DecisionCursor(decisions);
        var framingMode = cursor.Next() % 16;
        var chunkMode = cursor.Next() % 12;
        var pipelineMode = cursor.Next() % 6;
        var bodyLength = SemanticBodyLengths[cursor.Next() % SemanticBodyLengths.Length];
        var requestedChunkCount = 1 + cursor.Next() % 4;
        var extraHeaderMode = cursor.Next() % 8;
        var methodMode = cursor.Next() % 8;
        var pathMode = cursor.Next() % 6;
        var appMode = cursor.Next() % 5;

        var body = new byte[bodyLength];
        for (var i = 0; i < body.Length; i++)
        {
            body[i] = cursor.Next();
        }

        using var transcript = new MemoryStream(capacity: 1024);
        WriteRequestLine(transcript, methodMode, pathMode);
        WriteAscii(transcript, "Host: localhost\r\n");
        WriteAscii(transcript, $"X-TF-App-Mode: {appMode.ToString(CultureInfo.InvariantCulture)}\r\n");
        WriteExtraHeader(transcript, extraHeaderMode, cursor);
        WriteFramingHeaders(transcript, framingMode, chunkMode, body.Length);
        WriteAscii(transcript, "\r\n");
        WriteBody(transcript, framingMode, chunkMode, requestedChunkCount, body);
        WritePipeline(transcript, pipelineMode);
        return transcript.ToArray();
    }

    private static void WriteRequestLine(Stream output, int methodMode, int pathMode)
    {
        var method = methodMode switch
        {
            0 => "POST",
            1 => "PUT",
            2 => "PATCH",
            3 => "GET",
            4 => "OPTIONS",
            5 => "CONNECT",
            6 => "DELETE",
            _ => "PROPFIND",
        };

        var target = methodMode switch
        {
            4 => "*",
            5 => "localhost:443",
            _ => pathMode switch
            {
                0 => "/semantic",
                1 => "/semantic/a%2fb?q=x%20y",
                2 => "/semantic//double",
                3 => "/semantic/../dot",
                4 => "http://localhost/semantic/absolute",
                _ => "/semantic;param=value",
            },
        };

        WriteAscii(output, $"{method} {target} HTTP/1.1\r\n");
    }

    private static void WriteExtraHeader(Stream output, int mode, DecisionCursor cursor)
    {
        switch (mode)
        {
            case 1:
                WriteAscii(output, "Expect: 100-continue\r\n");
                break;
            case 2:
                WriteAscii(output, "Host: localhost\r\n");
                break;
            case 3:
                WriteAscii(output, "Host: conflicting.invalid\r\n");
                break;
            case 4:
                WriteAscii(output, "Trailer: X-TF-Trailer, X-TF-Second\r\n");
                break;
            case 5:
                WriteAscii(output, "Connection: keep-alive\r\n");
                break;
            case 6:
                WriteAscii(output, "TE: trailers\r\n");
                break;
            case 7:
                var paddingLength = 1 + cursor.Next() % 32;
                WriteAscii(output, $"X-TF-Pad: {new string('a', paddingLength)}\r\n");
                break;
        }
    }

    private static void WriteFramingHeaders(Stream output, int mode, int chunkMode, int bodyLength)
    {
        switch (mode)
        {
            case 0:
                WriteContentLength(output, bodyLength);
                break;
            case 1:
                WriteContentLength(output, bodyLength);
                WriteContentLength(output, bodyLength);
                break;
            case 2:
                WriteContentLength(output, bodyLength);
                WriteContentLength(output, bodyLength + 1);
                break;
            case 3:
                WriteAscii(output, $"Content-Length: {bodyLength}, {bodyLength}\r\n");
                break;
            case 4:
                WriteAscii(output, $"Content-Length: {bodyLength}, {bodyLength + 1}\r\n");
                break;
            case 5:
                WriteAscii(output, "Transfer-Encoding: chunked\r\n");
                break;
            case 6:
                WriteAscii(output, "Transfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n");
                break;
            case 7:
                WriteAscii(output, "Transfer-Encoding: gzip, chunked\r\n");
                break;
            case 8:
                WriteAscii(output, "Transfer-Encoding: chunked, gzip\r\n");
                break;
            case 9:
                WriteContentLength(output, bodyLength);
                WriteAscii(output, "Transfer-Encoding: chunked\r\n");
                break;
            case 10:
                WriteAscii(output, "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n");
                break;
            case 11:
                WriteContentLength(output, Math.Max(0, bodyLength - 1));
                break;
            case 12:
                WriteContentLength(output, bodyLength + 1);
                break;
            case 13:
                WriteAscii(output, "Transfer-Encoding: identity\r\n");
                break;
            case 14:
                break;
            case 15:
                WriteContentLength(output, 0);
                break;
        }

        if (IsChunkedMode(mode) && chunkMode is 10 or 11)
        {
            WriteAscii(output, "Trailer: X-TF-Trailer, X-TF-Second\r\n");
        }
    }

    private static void WriteContentLength(Stream output, int value) =>
        WriteAscii(output, $"Content-Length: {value.ToString(CultureInfo.InvariantCulture)}\r\n");

    private static void WriteBody(
        Stream output,
        int framingMode,
        int chunkMode,
        int requestedChunkCount,
        byte[] body)
    {
        if (IsChunkedMode(framingMode))
        {
            WriteChunkedBody(output, chunkMode, requestedChunkCount, body);
            return;
        }

        output.Write(body);
    }

    private static bool IsChunkedMode(int framingMode) => framingMode is >= 5 and <= 10;

    private static void WriteChunkedBody(Stream output, int mode, int requestedChunkCount, byte[] body)
    {
        if (mode == 3)
        {
            WriteAscii(output, "g\r\nsemantic\r\n0\r\n\r\n");
            return;
        }

        if (mode == 4)
        {
            WriteAscii(output, "10000000000000000\r\n");
            return;
        }

        var chunkCount = body.Length == 0 ? 0 : Math.Min(requestedChunkCount, body.Length);
        var offset = 0;
        for (var chunkIndex = 0; chunkIndex < chunkCount; chunkIndex++)
        {
            var remaining = body.Length - offset;
            var remainingChunks = chunkCount - chunkIndex;
            var chunkLength = (remaining + remainingChunks - 1) / remainingChunks;
            var advertisedLength = mode == 5 && chunkIndex == 0 ? chunkLength + 1 : chunkLength;
            var extension = mode switch
            {
                1 when chunkIndex == 0 => ";foo=bar;quoted=\"value\"",
                2 when chunkIndex == 0 => ";unterminated=\"value",
                _ => String.Empty,
            };

            WriteAscii(output, $"{advertisedLength:x}{extension}\r\n");
            output.Write(body, offset, chunkLength);
            offset += chunkLength;

            if (mode == 6 && chunkIndex == 0)
            {
                WriteAscii(output, "\n");
            }
            else if (mode != 7 || chunkIndex != 0)
            {
                WriteAscii(output, "\r\n");
            }
        }

        switch (mode)
        {
            case 8:
                WriteAscii(output, "0\n\n");
                break;
            case 9:
                WriteAscii(output, "0\r\n");
                break;
            case 10:
                WriteAscii(output, "0\r\nX-TF-Trailer: yes\r\nX-TF-Second: two\r\n\r\n");
                break;
            case 11:
                WriteAscii(output, "0\r\nContent-Length: 9\r\nX-TF-Trailer bad\r\n\r\n");
                break;
            default:
                WriteAscii(output, "0\r\n\r\n");
                break;
        }
    }

    private static void WritePipeline(Stream output, int mode)
    {
        switch (mode)
        {
            case 1:
                WriteAscii(output, "GET /semantic-next HTTP/1.1\r\nHost: localhost\r\n\r\n");
                break;
            case 2:
                WriteAscii(
                    output,
                    "POST /semantic-next HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n");
                break;
            case 3:
                WriteAscii(output, "OPTIONS * HTTP/1.1\r\nHost: localhost\r\n\r\n");
                break;
            case 4:
                WriteAscii(output, "GET /semantic-partial HTTP/1.1\r\nHost: localhost\r\n");
                break;
            case 5:
                WriteAscii(
                    output,
                    "GET http://localhost/semantic-absolute HTTP/1.1\r\nHost: localhost\r\n\r\n");
                break;
        }
    }

    private static void WriteAscii(Stream output, string text)
    {
        var bytes = Encoding.ASCII.GetBytes(text);
        output.Write(bytes);
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
