using System;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

class Program
{
    static void Main(string[] args)
    {
        if (args.Length < 1)
        {
            Console.WriteLine("Usage: Program.exe SWF_FILE [PASSWORD]");
            Console.WriteLine("If PASSWORD is provided, then a password will be required to view advanced telemetry in Monocle.");
            return;
        }

        string infile = args[0];
        string passwordClear = args.Length > 1 ? args[1] : null;

        using (var swfFH = new FileStream(infile, FileMode.Open, FileAccess.Read))
        using (var memoryStream = new MemoryStream())
        {
            byte[] signature = new byte[3];
            swfFH.Read(signature, 0, 3);
            byte swfVersion = (byte)swfFH.ReadByte();
            int length = ReadInt32(swfFH);

            if (Encoding.ASCII.GetString(signature) == "CWS")
            {
                using (var deflateStream = new DeflateStream(swfFH, CompressionMode.Decompress))
                {
                    deflateStream.CopyTo(memoryStream);
                }
            }
            else if (Encoding.ASCII.GetString(signature) == "ZWS")
            {
                throw new NotSupportedException("LZMA decompression not yet supported");
            }
            else if (Encoding.ASCII.GetString(signature) != "FWS")
            {
                throw new Exception($"Bad SWF: Unrecognized signature: {Encoding.ASCII.GetString(signature)}");
            }
            else
            {
                swfFH.CopyTo(memoryStream);
            }

            memoryStream.Seek(0, SeekOrigin.Begin);
            using (var output = new FileStream(infile, FileMode.Create, FileAccess.Write))
            {
                output.Write(signature, 0, 3);
                output.WriteByte(swfVersion);
                WriteInt32(output, 0); // Placeholder for length

                byte[] frameData = new byte[5];
                memoryStream.Read(frameData, 0, 5);
                output.Write(frameData, 0, 5);

                while (true)
                {
                    int tagType;
                    byte[] tagBytes = ConsumeSwfTag(memoryStream, out tagType);

                    if (tagType == 93)
                    {
                        throw new Exception("Bad SWF: already has EnableTelemetry tag");
                    }

                    if (tagType == 92)
                    {
                        throw new Exception("Bad SWF: Signed SWFs are not supported");
                    }

                    if (tagType == 69)
                    {
                        output.Write(tagBytes, 0, tagBytes.Length);

                        int nextTagType;
                        byte[] nextTagBytes = ConsumeSwfTag(memoryStream, out nextTagType);
                        bool writeAfterNextTag = nextTagType == 77;
                        if (writeAfterNextTag) output.Write(nextTagBytes, 0, nextTagBytes.Length);

                        OutputTelemetryTag(output, passwordClear);

                        if (!writeAfterNextTag) output.Write(nextTagBytes, 0, nextTagBytes.Length);
                    }

                    output.Write(tagBytes, 0, tagBytes.Length);

                    if (tagType == 0) break;
                }

                int uncompressedLength = (int)output.Position;
                output.Seek(4, SeekOrigin.Begin);
                WriteInt32(output, uncompressedLength);
            }

            Console.WriteLine(passwordClear != null
                ? $"Added opt-in flag with encrypted password {passwordClear}"
                : "Added opt-in flag with no password");
        }
    }

    static int ReadInt32(Stream stream)
    {
        byte[] buffer = new byte[4];
        stream.Read(buffer, 0, 4);
        return BitConverter.ToInt32(buffer, 0);
    }

    static void WriteInt32(Stream stream, int value)
    {
        byte[] buffer = BitConverter.GetBytes(value);
        stream.Write(buffer, 0, 4);
    }

    static byte[] ConsumeSwfTag(Stream stream, out int tagType)
    {
        byte[] recordHeaderRaw = new byte[2];
        if (stream.Read(recordHeaderRaw, 0, 2) != 2)
        {
            throw new Exception("Bad SWF: Unexpected end of file");
        }

        int tagCode = (recordHeaderRaw[1] << 8) | recordHeaderRaw[0];
        tagType = tagCode >> 6;
        int tagLength = tagCode & 0x3F;

        if (tagLength == 0x3F)
        {
            byte[] longLengthBytes = new byte[4];
            stream.Read(longLengthBytes, 0, 4);
            tagLength = BitConverter.ToInt32(longLengthBytes, 0);
        }

        byte[] tagData = new byte[tagLength];
        stream.Read(tagData, 0, tagLength);

        using (var memoryStream = new MemoryStream())
        {
            memoryStream.Write(recordHeaderRaw, 0, 2);
            if (tagLength == 0x3F)
            {
                memoryStream.Write(BitConverter.GetBytes(tagLength), 0, 4);
            }
            memoryStream.Write(tagData, 0, tagData.Length);
            return memoryStream.ToArray();
        }
    }

    static void OutputTelemetryTag(Stream stream, string passwordClear)
    {
        int lengthBytes = 2; // Reserve
        byte[] passwordDigest = null;

        if (!string.IsNullOrEmpty(passwordClear))
        {
            using (var sha256 = SHA256.Create())
            {
                passwordDigest = sha256.ComputeHash(Encoding.UTF8.GetBytes(passwordClear));
                lengthBytes += passwordDigest.Length;
            }
        }

        int code = 93;
        if (lengthBytes >= 63)
        {
            stream.Write(BitConverter.GetBytes((code << 6) | 0x3F), 0, 2);
            stream.Write(BitConverter.GetBytes(lengthBytes), 0, 4);
        }
        else
        {
            stream.Write(BitConverter.GetBytes((code << 6) | lengthBytes), 0, 2);
        }

        stream.Write(BitConverter.GetBytes(0), 0, 2); // Reserve

        if (passwordDigest != null)
        {
            stream.Write(passwordDigest, 0, passwordDigest.Length);
        }
    }
}
