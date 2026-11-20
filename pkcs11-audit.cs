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
                        CryptoUtils.ExtractWrappedKey(session, factories, privateKey);
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
                     ?? throw new Exception($"Token ({manufacturerId} {label}) either not found or there are 2+ such tokens.");

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
    
    public static void ExtractWrappedKey(ISession session, Pkcs11InteropFactories factories, IObjectHandle privateKey)
    {
        // Generate a random 256-bit AES wrapping key in local memory
        byte[] rawAesKey = RandomNumberGenerator.GetBytes(32);

        // Import the AES key into the token as a temporary session object (CKA_TOKEN = false)
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
            // Wrap the private key using AES Key Wrap with Padding (RFC 5649)
            using IMechanism wrapMechanism = factories.MechanismFactory.Create(CKM.CKM_AES_CBC_PAD);
            byte[] wrappedKeyBytes = session.WrapKey(wrapMechanism, wrappingKey, privateKey);

            Console.WriteLine($"Successfully wrapped key ({wrappedKeyBytes.Length} bytes).");
            UnwrapAndPrintPem(wrappedKeyBytes, rawAesKey);
        }
        finally
        {
            session.DestroyObject(wrappingKey);
        }
    }
    
    public static void UnwrapAndPrintPem(byte[] wrappedKeyBytes, byte[] rawAesKey)
    {
        // 1. Initialize the RFC 5649 (AES Key Wrap with Padding) engine for decryption
        var wrapEngine = new Rfc5649WrapEngine(new AesEngine());
        wrapEngine.Init(forWrapping: false, new KeyParameter(rawAesKey));

        // 2. Unwrap the ciphertext to recover the raw ASN.1 DER PKCS#8 PrivateKeyInfo bytes
        byte[] pkcs8DerBytes = wrapEngine.Unwrap(wrappedKeyBytes, 0, wrappedKeyBytes.Length);

        // 3. Load into .NET's native RSA (or ECDsa) class and export as PEM
        using RSA rsa = RSA.Create();
        rsa.ImportPkcs8PrivateKey(pkcs8DerBytes, out _);

        string pem = rsa.ExportPkcs8PrivateKeyPem();
        Console.WriteLine("\nUnwrapped PEM Private Key:\n" + pem);

        // Optional: Zero out sensitive key material in memory when done
        CryptographicOperations.ZeroMemory(pkcs8DerBytes);
    }
}