#:sdk Microsoft.NET.Sdk
#:package CommandLineParser@2.9.1
#:package Pkcs11Interop@5.3.0
#:package BouncyCastle.Cryptography@2.8.0-beta.349

using System.Security.Cryptography;
using CommandLine;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

CryptoUtils.WorkWithToken(AppState.ParsedArgs.Pkcs11Module!, AppState.ParsedArgs.ManufacturerId!,
    AppState.ParsedArgs.Label!,
    (slot, session, factories) =>
    {
        session.Login(CKU.CKU_USER, AppState.ParsedArgs.PinCode);
        try
        {
            if (bool.TryParse(AppState.ParsedArgs.Testing, out var res) && !res)
            {
                Console.WriteLine("Creating set of vulnerable keys...");
                CryptoUtils.GeneratePrivKeyWithFlags(session, true, true);
                Console.WriteLine("Generated extractable + sensitive key pair");
                CryptoUtils.GeneratePrivKeyWithFlags(session, true, false);
                Console.WriteLine("Generated extractable only key pair");
            }
            else
            {
                var searchTemplate = new List<IObjectAttribute>
                    { factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY) };
                foreach (var privateKey in session.FindAllObjects(searchTemplate))
                {
                    // 4. Inspect CKA_EXTRACTABLE and CKA_SENSITIVE
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

    public static void GeneratePrivKeyWithFlags(ISession session, bool extractable, bool sensitive)
    {
        // The CKA_ID attribute is intended as a means of distinguishing multiple key pairs held by the same subject
        byte[] ckaId = session.GenerateRandom(20);
        var label = $"DTM_{Guid.NewGuid()}";

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

        // Load components into .NET's native RSA class to export as PEM
        var rsaParams = new RSAParameters
        {
            Modulus = values[0].GetValueAsByteArray(),
            Exponent = values[1].GetValueAsByteArray(),
            D = values[2].GetValueAsByteArray(),
            P = values[3].GetValueAsByteArray(),
            Q = values[4].GetValueAsByteArray(),
            DP = values[5].GetValueAsByteArray(),
            DQ = values[6].GetValueAsByteArray(),
            InverseQ = values[7].GetValueAsByteArray()
        };

        using RSA rsa = RSA.Create(rsaParams);
        string pem = rsa.ExportPkcs8PrivateKeyPem();
        Console.WriteLine("\nExtracted PEM Private Key:\n" + pem);
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