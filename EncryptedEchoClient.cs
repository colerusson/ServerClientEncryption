using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Logging;

/// <summary>
/// Provides a base class for implementing an Echo client.
/// </summary>
internal sealed class EncryptedEchoClient : EchoClientBase
{

    /// <summary>
    /// Logger to use in this class.
    /// </summary>
    private ILogger<EncryptedEchoClient> Logger { get; init; } =
        Settings.LoggerFactory.CreateLogger<EncryptedEchoClient>()!;

    /// <inheritdoc />
    public EncryptedEchoClient(ushort port, string address) : base(port, address) { }

    private RSA? serverPublicKey;

    /// <inheritdoc />
    public override void ProcessServerHello(string message)
    {
        // todo: Step 1: Get the server's public key. Decode using Base64.
        // Throw a CryptographicException if the received key is invalid.
        try
        {
            serverPublicKey = RSA.Create();
            serverPublicKey.ImportRSAPublicKey(Convert.FromBase64String(message), out _);
        }
        catch (CryptographicException e)
        {
            Logger.LogError(e, "The server's public key is invalid.");
            throw;
        }
    }

    /// <inheritdoc />
    public override string TransformOutgoingMessage(string input)
    {
        byte[] data = Settings.Encoding.GetBytes(input);

        // todo: Step 1: Encrypt the input using hybrid encryption.
        // Encrypt using AES with CBC mode and PKCS7 padding.
        // Use a different key each time.
        byte[] aesKey;
        byte[] aesIV;
        byte[] hmacKey;
        byte[] hmac;

        using (Aes aes = Aes.Create())
        {
            aesKey = aes.Key;
            aesIV = aes.IV;

            // Generate a separate key for HMAC calculation
            using (HMACSHA256 hmacAlg = new HMACSHA256())
            {
                hmacKey = hmacAlg.Key;

                // Encrypt the AES key
                byte[] encryptedAesKey = serverPublicKey!.Encrypt(aesKey, RSAEncryptionPadding.OaepSHA256);

                // Encrypt the HMAC key
                byte[] encryptedHmacKey = serverPublicKey.Encrypt(hmacKey, RSAEncryptionPadding.OaepSHA256);

                // Use the separate HMAC key for HMAC calculation
                hmac = hmacAlg.ComputeHash(data);

                // Encrypt the message data using AES
                byte[] encryptedData;
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(data);
                        cs.FlushFinalBlock();
                        encryptedData = ms.ToArray();
                    }
                }

                // Create the EncryptedMessage object
                var message = new EncryptedMessage(encryptedAesKey, aesIV, encryptedData, encryptedHmacKey, hmac);

                // Serialize and return the message
                return JsonSerializer.Serialize(message);
            }
        }
    }

    /// <inheritdoc />
    public override string TransformIncomingMessage(string input)
    {
        // todo: Step 1: Deserialize the message.
        var signedMessage = JsonSerializer.Deserialize<SignedMessage>(input);

        // todo: Step 2: Check the messages signature.
        // Use PSS padding with SHA256.
        // Throw an InvalidSignatureException if the signature is bad.
        if (!serverPublicKey!.VerifyData(signedMessage.Message, signedMessage.Signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss))
        {
            throw new InvalidSignatureException("Invalid signature detected.");
        }

        // todo: Step 3: Return the message from the server.
        return Settings.Encoding.GetString(signedMessage.Message);
    }
}