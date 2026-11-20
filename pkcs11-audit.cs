#:sdk Microsoft.NET.Sdk
#:package CommandLineParser@2.9.1
#:package Pkcs11Interop@5.3.0
#:package BouncyCastle.Cryptography@2.8.0-beta.349

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CommandLine;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;

CryptoUtils.WorkWithToken(AppState.ParsedArgs.Pkcs11Module!, AppState.ParsedArgs.ManufacturerId!,
    AppState.ParsedArgs.Label!,
    (slot, session, factories) =>
    {
        session.Login(CKU.CKU_USER, AppState.ParsedArgs.PinCode);
        try
        {
            if (bool.TryParse(AppState.ParsedArgs.Testing, out var res) && !res)
            {
                bool.TryParse(AppState.ParsedArgs.GenerateKeysOnToken, out var genOnToken);
                Console.WriteLine($"Keys generated on token: {genOnToken}");
                
                Console.WriteLine("Creating set of vulnerable keys...");
                CryptoUtils.GeneratePrivKeyWithFlags(session, true, true, genOnToken);
                Console.WriteLine("Generated extractable + sensitive key pair");
                CryptoUtils.GeneratePrivKeyWithFlags(session, true, false, genOnToken);
                Console.WriteLine("Generated extractable only key pair");
            }
            else
            {
                var searchTemplate = new List<IObjectAttribute>
                    { factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY) };
                foreach (var privateKey in session.FindAllObjects(searchTemplate))
                {
                    try
                    {
                        var flagAttrs = session.GetAttributeValue(privateKey, [
                            CKA.CKA_EXTRACTABLE,
                            CKA.CKA_SENSITIVE,
                            CKA.CKA_LABEL
                        ]);
                        var isExtractable = flagAttrs[0].GetValueAsBool();
                        var isSensitive = flagAttrs[1].GetValueAsBool();
                        var label = flagAttrs[2].GetValueAsString();

                        Console.WriteLine($"Processing key labeled as: {label}");

                        if (!isExtractable)
                        {
                            Console.WriteLine("Extraction blocked: CKA_EXTRACTABLE is FALSE.");
                            continue;
                        }

                        if (!isSensitive)
                        {
                            Console.WriteLine("Key is non-sensitive. Reading components directly...");
                            CryptoUtils.ExtractPlaintextRsaKey(session, privateKey);
                        }
                        else
                        {
                            Console.WriteLine("Key is sensitive. Exporting via AES Key Wrap...");
                            CryptoUtils.ExtractWrappedKey(slot, session, factories, privateKey);
                        }
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e);
                    }
                }
            }
        }
        finally
        {
            session.Logout();
        }
    });


public static class AppState
{
    public static readonly AuditArgs ParsedArgs;

    static AppState()
    {
        AuditArgs? parsed = null;
        CommandLine.Parser.Default.ParseArguments<AuditArgs>(Environment.GetCommandLineArgs())
            .WithParsed(options => parsed = options)
            .WithNotParsed(errors => Environment.Exit(0));
        ParsedArgs = parsed!;
    }
}

public class AuditArgs
{
    [Option("module", Required = true, HelpText = "PKCS#11 .dll module for interaction with token")]
    public string? Pkcs11Module { get; set; }

    [Option("pin", Required = true, HelpText = "PIN code for token operations")]
    public string? PinCode { get; set; }

    [Option("manufacturer", Required = true, HelpText = "Manufacturer ID of the token")]
    public string? ManufacturerId { get; set; }

    [Option("label", Required = true, HelpText = "Label of the token")]
    public string? Label { get; set; }

    [Option("testing", Required = true,
        HelpText = "If true token is only tested, vulnerable key set is generated otherwise")]
    public string? Testing { get; set; }
    
    [Option("gen-keys-on-token", 
        HelpText = "Decides whether private keys should be generated on user side or on token side")]
    public string? GenerateKeysOnToken { get; set; }
}

public static class CryptoUtils
{
    public static void WorkWithToken(string libpath, string manufacturerId, string label,
        Action<ISlot, ISession, Pkcs11InteropFactories> test)
    {
        Pkcs11InteropFactories factories = new Pkcs11InteropFactories();
        using IPkcs11Library pkcs11Library =
            factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, libpath, AppType.MultiThreaded);

        List<ISlot> slots = pkcs11Library.GetSlotList(SlotsType.WithTokenPresent);
        if (slots.Count == 0)
            throw new Exception("No slots found.");
        ISlot slot = slots.SingleOrDefault(s =>
                         s.GetSlotInfo().ManufacturerId
                             .Contains(manufacturerId, StringComparison.InvariantCultureIgnoreCase)
                         && s.GetTokenInfo().Label.Contains(label, StringComparison.InvariantCultureIgnoreCase))
                     ?? throw new Exception(
                         $"Token ({manufacturerId} {label}) either not found or there are 2+ such tokens.");

        using ISession session = slot.OpenSession(SessionType.ReadWrite);
        test(slot, session, factories);
    }

    public static void GeneratePrivKeyWithFlags(ISession session, bool extractable, bool sensitive, bool generateOnToken)
    {
        // The CKA_ID attribute is intended as a means of distinguishing multiple key pairs held by the same subject
        byte[] ckaId = session.GenerateRandom(20);
        var label = $"DTM_{Guid.NewGuid()}";

        if (generateOnToken)
            GenerateKeyOnToken(session, label, ckaId, extractable, sensitive);
        else
            GenerateKeyOnMachineAndExportOnToken(session, label, ckaId, extractable, sensitive);
    }

    public static void ExtractPlaintextRsaKey(ISession session, IObjectHandle privateKey)
    {
        var rsaAttributes = new List<CKA>
        {
            CKA.CKA_MODULUS,
            CKA.CKA_PUBLIC_EXPONENT,
            CKA.CKA_PRIVATE_EXPONENT,
            CKA.CKA_PRIME_1,
            CKA.CKA_PRIME_2,
            CKA.CKA_EXPONENT_1,
            CKA.CKA_EXPONENT_2,
            CKA.CKA_COEFFICIENT
        };

        List<IObjectAttribute> values = session.GetAttributeValue(privateKey, rsaAttributes);

        // Helper: strip leading 0x00 bytes from big-endian unsigned integer
        static byte[] TrimLeadingZeros(byte[] data)
        {
            if (data == null || data.Length == 0) return Array.Empty<byte>();
            int i = 0;
            while (i < data.Length - 1 && data[i] == 0) i++;
            return data[i..];
        }

        // Helper: left-pad with 0x00 to reach exact target length required by Windows CNG
        static byte[] NormalizeLength(byte[] data, int targetLen)
        {
            byte[] trimmed = TrimLeadingZeros(data);
            if (trimmed.Length == targetLen) return trimmed;
            if (trimmed.Length > targetLen)
                throw new InvalidOperationException(
                    $"Component length ({trimmed.Length}) exceeds expected ({targetLen}).");

            byte[] padded = new byte[targetLen];
            Buffer.BlockCopy(trimmed, 0, padded, targetLen - trimmed.Length, trimmed.Length);
            return padded;
        }

        byte[] modulus = TrimLeadingZeros(values[0].GetValueAsByteArray());
        int modLen = modulus.Length;
        int halfLen = (modLen + 1) / 2;

        byte[] exponent = TrimLeadingZeros(values[1].GetValueAsByteArray());
        byte[] d = NormalizeLength(values[2].GetValueAsByteArray(), modLen);

        // Check if CRT parameters (P, Q, DP, DQ, InverseQ) are populated by the token
        bool hasCrt = !values[3].CannotBeRead && values[3].GetValueAsByteArray()?.Length > 0 &&
                      !values[4].CannotBeRead && values[4].GetValueAsByteArray()?.Length > 0;

        if (hasCrt)
        {
            var rsaParams = new RSAParameters
            {
                Modulus = modulus,
                Exponent = exponent,
                D = d,
                P = NormalizeLength(values[3].GetValueAsByteArray(), halfLen),
                Q = NormalizeLength(values[4].GetValueAsByteArray(), halfLen),
                DP = NormalizeLength(values[5].GetValueAsByteArray(), halfLen),
                DQ = NormalizeLength(values[6].GetValueAsByteArray(), halfLen),
                InverseQ = NormalizeLength(values[7].GetValueAsByteArray(), halfLen)
            };

            using RSA rsa = RSA.Create(rsaParams);
            Console.WriteLine("\nExtracted PEM Private Key:\n" + rsa.ExportPkcs8PrivateKeyPem());
        }
        else
        {
            // Fallback if token only stores (N, E, D) without P, Q, DP, DQ, InverseQ:
            // Use BouncyCastle to export PKCS#8 directly from (N, E, D)
            var bcKey = new Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters(
                isPrivate: true,
                new Org.BouncyCastle.Math.BigInteger(1, modulus),
                new Org.BouncyCastle.Math.BigInteger(1, d));

            byte[] pkcs8 = Org.BouncyCastle.Pkcs.PrivateKeyInfoFactory.CreatePrivateKeyInfo(bcKey).GetEncoded();
            Console.WriteLine("\nExtracted PKCS#8 Base64 (Non-CRT):\n-----BEGIN PRIVATE KEY-----\n" +
                              Convert.ToBase64String(pkcs8, Base64FormattingOptions.InsertLineBreaks) +
                              "\n-----END PRIVATE KEY-----");
        }
    }

    private static void GenerateKeyOnMachineAndExportOnToken(ISession session, string label, byte[] ckaId,
        bool extractable, bool sensitive)
    {
        var cert = GenerateCertificate("aaa");
        RSAParameters rsaParams = ExportRsaPrivateKey(cert);
        var keyAttributes = new List<IObjectAttribute>
        {
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_RSA),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, label),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, ckaId),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, true),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SENSITIVE, sensitive),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_EXTRACTABLE, extractable),
            // RSA Components
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_MODULUS, rsaParams.Modulus),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PUBLIC_EXPONENT, rsaParams.Exponent),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE_EXPONENT, rsaParams.D),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIME_1, rsaParams.P),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIME_2, rsaParams.Q),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_EXPONENT_1, rsaParams.DP),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_EXPONENT_2, rsaParams.DQ),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_COEFFICIENT, rsaParams.InverseQ)
        };
        session.CreateObject(keyAttributes);
    }

    private static void GenerateKeyOnToken(ISession session, string label, byte[] ckaId, bool extractable, bool sensitive)
    {
        // Prepare attribute template of new public key
        List<IObjectAttribute> publicKeyAttributes =
        [
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, false),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, label),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, ckaId),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ENCRYPT, true),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_VERIFY, true),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_VERIFY_RECOVER, true),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_WRAP, false),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_MODULUS_BITS, 2048),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PUBLIC_EXPONENT, [0x01, 0x00, 0x01]),
        ];

        // Prepare attribute template of new private key
        List<IObjectAttribute> privateKeyAttributes =
        [
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, true),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, label),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, ckaId),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SENSITIVE, sensitive),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_EXTRACTABLE, extractable),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_DECRYPT, true),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SIGN, true),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SIGN_RECOVER, true),
            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_UNWRAP, false),
        ];

        // Specify key generation mechanism
        IMechanism mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN);

        // Generate key pair
        session.GenerateKeyPair(mechanism, publicKeyAttributes, privateKeyAttributes, out _, out _);
    } 

    private static X509Certificate2 GenerateCertificate(string subjectName)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest($"CN={subjectName}", rsa, HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DataEncipherment, critical: true));

        var certSelfSigned = request.CreateSelfSigned(DateTime.UtcNow, DateTime.MaxValue);

        var export = certSelfSigned.Export(X509ContentType.Pfx, "");
        var cert = new X509Certificate2(export, "",
            X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);

        // To persist the private key
        var certWithPubKeyOnly = new X509Certificate2(cert.RawData);
        var certWithPrivateKey = certWithPubKeyOnly.CopyWithPrivateKey(rsa);

        return certWithPrivateKey;
    }
    
    private static RSAParameters ExportRsaPrivateKey(X509Certificate2 cert)
    {
        using var rsa = cert.GetRSAPrivateKey()!;
        // 1. У вас есть байты закрытого ключа (PKCS#8)
        byte[] keyBytes = rsa.ExportPkcs8PrivateKey();

        // 2. Создаем временный объект RSA и импортируем байты
        using RSA tempRsa = RSA.Create();
        tempRsa.ImportPkcs8PrivateKey(keyBytes, out _);

        // 3. Экспортируем параметры
        // true означает, что нужно включить закрытые параметры (D, P, Q и т.д.)
        return tempRsa.ExportParameters(true);
    }

    public static void ExtractWrappedKey(ISlot slot, ISession session, Pkcs11InteropFactories factories,
        IObjectHandle privateKey)
    {
        // 1. Discover all mechanisms on this slot that support wrapping
        var supportedWrapMechs = slot.GetMechanismList()
            .Where(m => slot.GetMechanismInfo(m).MechanismFlags.Wrap)
            .ToHashSet();

        // 2. Pick the best AES wrapping mechanism in order of preference
        CKM chosenMech;
        if (supportedWrapMechs.Contains(CKM.CKM_AES_KEY_WRAP_PAD))
            chosenMech = CKM.CKM_AES_KEY_WRAP_PAD;
        else if (supportedWrapMechs.Contains(CKM.CKM_AES_KEY_WRAP))
            chosenMech = CKM.CKM_AES_KEY_WRAP;
        else if (supportedWrapMechs.Contains(CKM.CKM_AES_CBC_PAD))
            chosenMech = CKM.CKM_AES_CBC_PAD;
        else
            throw new NotSupportedException(
                "No supported AES wrap mechanism found. Available wrap mechanisms: " +
                string.Join(", ", supportedWrapMechs));

        Console.WriteLine($"Selected wrapping mechanism: {chosenMech}");

        // 3. Create ephemeral AES-256 session wrapping key
        byte[] rawAesKey = RandomNumberGenerator.GetBytes(32);
        var wrapKeyTemplate = new List<IObjectAttribute>
        {
            factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
            factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_AES),
            factories.ObjectAttributeFactory.Create(CKA.CKA_VALUE, rawAesKey),
            factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, false),
            factories.ObjectAttributeFactory.Create(CKA.CKA_WRAP, true)
        };

        IObjectHandle wrappingKey = session.CreateObject(wrapKeyTemplate);

        try
        {
            byte[] iv = RandomNumberGenerator.GetBytes(16);

            // 4. Build mechanism parameters (only CKM_AES_CBC_PAD takes a 16-byte IV)
            using IMechanism mechanism = chosenMech == CKM.CKM_AES_CBC_PAD
                ? factories.MechanismFactory.Create(chosenMech, iv)
                : factories.MechanismFactory.Create(chosenMech);

            byte[] wrappedKeyBytes = session.WrapKey(mechanism, wrappingKey, privateKey);

            // 5. Unwrap locally using the matching algorithm
            byte[] pkcs8DerBytes = chosenMech switch
            {
                CKM.CKM_AES_KEY_WRAP_PAD => UnwrapRfc5649(wrappedKeyBytes, rawAesKey),
                CKM.CKM_AES_KEY_WRAP => UnwrapRfc3394(wrappedKeyBytes, rawAesKey),
                CKM.CKM_AES_CBC_PAD => UnwrapAesCbcPad(wrappedKeyBytes, rawAesKey, iv),
                _ => throw new NotSupportedException()
            };

            try
            {
                // Load into RSA (or swap for ECDsa.Create() if extracting an EC key)
                using RSA rsa = RSA.Create();
                rsa.ImportPkcs8PrivateKey(pkcs8DerBytes, out _);
                Console.WriteLine("\nUnwrapped PEM Private Key:\n" + rsa.ExportPkcs8PrivateKeyPem());
            }
            finally
            {
                CryptographicOperations.ZeroMemory(pkcs8DerBytes);
            }
        }
        finally
        {
            session.DestroyObject(wrappingKey);
            CryptographicOperations.ZeroMemory(rawAesKey);
        }
    }

    private static byte[] UnwrapRfc5649(byte[] wrapped, byte[] key)
    {
        var engine =
            new Org.BouncyCastle.Crypto.Engines.Rfc5649WrapEngine(new Org.BouncyCastle.Crypto.Engines.AesEngine());
        engine.Init(false, new Org.BouncyCastle.Crypto.Parameters.KeyParameter(key));
        return engine.Unwrap(wrapped, 0, wrapped.Length);
    }

    private static byte[] UnwrapRfc3394(byte[] wrapped, byte[] key)
    {
        var engine = new Org.BouncyCastle.Crypto.Engines.AesWrapEngine();
        engine.Init(false, new Org.BouncyCastle.Crypto.Parameters.KeyParameter(key));
        return engine.Unwrap(wrapped, 0, wrapped.Length);
    }

    private static byte[] UnwrapAesCbcPad(byte[] wrapped, byte[] key, byte[] iv)
    {
        using Aes aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        using ICryptoTransform decryptor = aes.CreateDecryptor();
        return decryptor.TransformFinalBlock(wrapped, 0, wrapped.Length);
    }
}