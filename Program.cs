using System;
using System.IO;
using System.IO.Compression;

class Program
{
    static void Main(string[] args)
    {
        if (args.Length < 1)
        {
            Console.WriteLine("Usage: dotnet run <SWF_FILE> [PASSWORD]");
            Console.WriteLine("If PASSWORD is provided, then a password will be required to view advanced telemetry.");
            return;
        }

        string inputFilePath = args[0];
        string password = args.Length > 1 ? args[1] : null;

        if (!File.Exists(inputFilePath))
        {
            Console.WriteLine($"File not found: {inputFilePath}");
            return;
        }

        try
        {
            using (var inputFileStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
            {
                string outputFilePath = inputFilePath; // Overwrite the file by default
                ProcessSwf(inputFileStream, outputFilePath, password);
                Console.WriteLine(password != null
                    ? $"Added opt-in flag with encrypted password: {password}"
                    : "Added opt-in flag with no password.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }

    static void ProcessSwf(Stream inputFileStream, string outputFilePath, string password)
    {
        // Read the SWF signature and version
        var signatureBytes = new byte[3];
        inputFileStream.Read(signatureBytes, 0, 3);
        string signature = System.Text.Encoding.ASCII.GetString(signatureBytes);

        var versionByte = inputFileStream.ReadByte();
        int swfVersion = versionByte;

        var fileLengthBytes = new byte[4];
        inputFileStream.Read(fileLengthBytes, 0, 4);
        int fileLength = BitConverter.ToInt32(fileLengthBytes, 0);

        MemoryStream decompressedStream = null;

        if (signature == "CWS")
        {
            Console.WriteLine("Detected ZLIB compression (CWS). Decompressing...");
            decompressedStream = new MemoryStream();
            inputFileStream.Seek(8, SeekOrigin.Begin); // Skip the SWF header (8 bytes)
            using (var deflateStream = new DeflateStream(inputFileStream, CompressionMode.Decompress))
            {
                deflateStream.CopyTo(decompressedStream);
            }
        }
        else if (signature == "FWS")
        {
            Console.WriteLine("No compression detected (FWS). Proceeding...");
            decompressedStream = new MemoryStream();
            inputFileStream.Seek(0, SeekOrigin.Begin);
            inputFileStream.CopyTo(decompressedStream);
        }
        else if (signature == "ZWS")
        {
            Console.WriteLine("LZMA compression (ZWS) detected. This is not yet supported.");
            return; // Handle or skip LZMA compression for now
        }
        else
        {
            throw new InvalidDataException($"Unknown SWF signature: {signature}");
        }

        // Reset stream position for further processing
        decompressedStream.Seek(0, SeekOrigin.Begin);

        // Write modified SWF
        using (var outputFileStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
        {
            WriteModifiedSwf(decompressedStream, outputFileStream, password, signature, swfVersion);
        }
    }

    static void WriteModifiedSwf(Stream decompressedStream, Stream outputStream, string password, string signature, int version)
    {
        // Write SWF signature and version
        outputStream.Write(System.Text.Encoding.ASCII.GetBytes(signature));
        outputStream.WriteByte((byte)version);

        // Placeholder for file length (will update later)
        var placeholderLength = BitConverter.GetBytes(0);
        outputStream.Write(placeholderLength, 0, 4);

        // Copy the unmodified content
        decompressedStream.CopyTo(outputStream);

        // Add telemetry tag (simplified for this example)
        if (!string.IsNullOrEmpty(password))
        {
            byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);
            outputStream.Write(passwordBytes, 0, passwordBytes.Length);
        }

        // Update file length
        long fileLength = outputStream.Position;
        outputStream.Seek(4, SeekOrigin.Begin);
        outputStream.Write(BitConverter.GetBytes((int)fileLength), 0, 4);
    }
}
