using System.Buffers;
using System.Globalization;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core.Internal.Http;
using SharpFuzz;

namespace KestrelHttp1Fuzz;

internal static class Program
{
    private const int MaxInputLength = 64 * 1024;

    public static void Main()
    {
        // Keep the main memory-safety lane on standards-compliant CRLF framing. The default
        // Kestrel compatibility mode permits bare LF and has a separately preserved,
        // network-confirmed short-header segmentation differential that otherwise dominates
        // AFL's crash queue.
        if (Environment.GetEnvironmentVariable("TF_KESTREL_STRICT_CRLF") != "0")
        {
            AppContext.SetSwitch(
                "Microsoft.AspNetCore.Server.Kestrel.DisableHttp1LineFeedTerminators",
                isEnabled: true);
        }

        Fuzzer.OutOfProcess.Run(stream =>
        {
            using var input = new MemoryStream();
            stream.CopyTo(input);
            if (input.Length > MaxInputLength)
            {
                return;
            }

            var bytes = input.ToArray();
            var contiguous = Parse(new ReadOnlySequence<byte>(bytes));
            var patterned = Parse(CreateSegmented(bytes, PatternedChunkSizes(bytes)));

            AssertEquivalent(contiguous, patterned, "patterned");

            if (bytes.Length <= 2048)
            {
                var bytewise = Parse(CreateSegmented(bytes, BytewiseChunkSizes(bytes.Length)));
                AssertEquivalent(contiguous, bytewise, "bytewise");
            }
        });
    }

    private static ParseOutcome Parse(ReadOnlySequence<byte> input)
    {
        var parser = new HttpParser<CaptureHandler>(showErrorDetails: false);
        var handler = new CaptureHandler();
        var reader = new SequenceReader<byte>(input);

        try
        {
            var requestLineComplete = parser.ParseRequestLine(handler, ref reader);
            var headersComplete = requestLineComplete && parser.ParseHeaders(handler, ref reader);
            return new ParseOutcome(
                RequestLineComplete: requestLineComplete,
                HeadersComplete: headersComplete,
                Consumed: reader.Consumed,
                BadRequestStatus: null,
                Signature: handler.Signature);
        }
        catch (BadHttpRequestException ex)
        {
            return new ParseOutcome(
                RequestLineComplete: false,
                HeadersComplete: false,
                Consumed: reader.Consumed,
                BadRequestStatus: ex.StatusCode,
                Signature: handler.Signature);
        }
    }

    private static void AssertEquivalent(ParseOutcome expected, ParseOutcome actual, string segmentation)
    {
        // A rejected request closes the HTTP/1 connection. The exact reader position and any
        // callbacks made before the rejection are not externally observable after that point,
        // and may legitimately differ when CR/LF crosses a sequence boundary.
        if (expected.BadRequestStatus is not null || actual.BadRequestStatus is not null)
        {
            if (expected.BadRequestStatus == actual.BadRequestStatus)
            {
                return;
            }

            // ParseMultiSpanHeader has a known short-header differential: a syntactically
            // valid empty-value header can be accepted in one segment and rejected when its
            // terminator crosses segments. Preserve and replay that family separately so AFL
            // can spend its crash budget on unrelated parser behavior.
            var accepted = expected.BadRequestStatus is null ? expected : actual;
            if (HasEmptyHeader(accepted.Signature))
            {
                return;
            }

            throw new InvalidDataException(
                $"Kestrel HTTP/1 accept/reject divergence ({segmentation}). " +
                $"contiguous={expected}; segmented={actual}");
        }

        if (expected != actual)
        {
            throw new InvalidDataException(
                $"Kestrel HTTP/1 segmentation divergence ({segmentation}). " +
                $"contiguous={expected}; segmented={actual}");
        }
    }

    private static bool HasEmptyHeader(string signature)
    {
        return signature.Split(';', StringSplitOptions.RemoveEmptyEntries)
            .Any(part =>
                (part.StartsWith("H:", StringComparison.Ordinal) ||
                 part.StartsWith("S:", StringComparison.Ordinal)) &&
                part.EndsWith(':'));
    }

    private static IEnumerable<int> PatternedChunkSizes(byte[] input)
    {
        if (input.Length == 0)
        {
            yield break;
        }

        var cursor = 0;
        var selector = input[0];
        while (cursor < input.Length)
        {
            var source = input[(cursor + selector) % input.Length];
            var size = 1 + (source % 31);
            size = Math.Min(size, input.Length - cursor);
            yield return size;
            cursor += size;
            selector = unchecked((byte)(selector * 33 + source));
        }
    }

    private static IEnumerable<int> BytewiseChunkSizes(int length)
    {
        for (var i = 0; i < length; i++)
        {
            yield return 1;
        }
    }

    private static ReadOnlySequence<byte> CreateSegmented(byte[] input, IEnumerable<int> chunkSizes)
    {
        if (input.Length == 0)
        {
            return ReadOnlySequence<byte>.Empty;
        }

        BufferSegment? first = null;
        BufferSegment? last = null;
        var offset = 0;

        foreach (var requestedSize in chunkSizes)
        {
            if (offset >= input.Length)
            {
                break;
            }

            var size = Math.Min(requestedSize, input.Length - offset);
            var segment = new BufferSegment(input.AsMemory(offset, size));
            if (first is null)
            {
                first = segment;
            }
            else
            {
                last!.Append(segment);
            }

            last = segment;
            offset += size;
        }

        if (offset != input.Length || first is null || last is null)
        {
            throw new InvalidOperationException("The segment builder did not consume the complete input.");
        }

        return new ReadOnlySequence<byte>(first, 0, last, last.Memory.Length);
    }

    private sealed class BufferSegment : ReadOnlySequenceSegment<byte>
    {
        public BufferSegment(ReadOnlyMemory<byte> memory)
        {
            Memory = memory;
        }

        public void Append(BufferSegment next)
        {
            next.RunningIndex = RunningIndex + Memory.Length;
            Next = next;
        }
    }

    private sealed class CaptureHandler : IHttpRequestLineHandler, IHttpHeadersHandler
    {
        private readonly StringBuilder _signature = new();

        public string Signature => _signature.ToString();

        public void OnStartLine(
            HttpVersionAndMethod versionAndMethod,
            TargetOffsetPathLength targetPath,
            Span<byte> startLine)
        {
            _signature.Append("L:")
                .Append((int)versionAndMethod.Method).Append(':')
                .Append((int)versionAndMethod.Version).Append(':')
                .Append(versionAndMethod.MethodEnd).Append(':')
                .Append(targetPath.Offset).Append(':')
                .Append(targetPath.Length).Append(':')
                .Append(targetPath.IsEncoded ? '1' : '0').Append(':')
                .Append(Convert.ToHexString(startLine)).Append(';');
        }

        public void OnHeader(ReadOnlySpan<byte> name, ReadOnlySpan<byte> value)
        {
            _signature.Append("H:")
                .Append(Convert.ToHexString(name)).Append(':')
                .Append(Convert.ToHexString(value)).Append(';');
        }

        public void OnHeadersComplete(bool endStream)
        {
            _signature.Append("E:").Append(endStream ? '1' : '0').Append(';');
        }

        public void OnStaticIndexedHeader(int index)
        {
            _signature.Append("S:").Append(index.ToString(CultureInfo.InvariantCulture)).Append(';');
        }

        public void OnStaticIndexedHeader(int index, ReadOnlySpan<byte> value)
        {
            _signature.Append("S:")
                .Append(index.ToString(CultureInfo.InvariantCulture)).Append(':')
                .Append(Convert.ToHexString(value)).Append(';');
        }
    }

    private readonly record struct ParseOutcome(
        bool RequestLineComplete,
        bool HeadersComplete,
        long Consumed,
        int? BadRequestStatus,
        string Signature);
}
