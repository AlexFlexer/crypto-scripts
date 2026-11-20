# Cryptography Scripts
My personal repository of cryptography-related API examples, scripts, and maybe even pentest tools. Everything you see in this repo is for educational purposes only.

Basically, this is just a bunch of so-called "file-based apps" (dotnet), they can be launched using single console command. 

I chose dotnet because I mostly work with c# at this point of my life, and dotnet seems to be mature ecosystem with wide range of possibilities.

## PKCS#11 audit
A simple tool that checks private keys on pkcs11 devices for extractability. Supports two operational modes:

1. **Testing.** Tries to extract private RSA-keys from the token, outputs them in PEM-format if succeeds.
```
dotnet run pkcs11-audit.cs -- --module "D:\SoftHSM2\lib\softhsm2-x64.dll" --pin 0000 --manufacturer softhsm --label mytoken --testing true
```

2. **Not testing.** Generates private RSA-keys right on the device using weak configs (extractable = true). Supports two modes:

Keys generated on token:
```
dotnet run pkcs11-audit.cs -- --module "D:\SoftHSM2\lib\softhsm2-x64.dll" --pin 0000 --manufacturer softhsm --label mytoken --testing false --gen-keys-on-token true
```

Keys generated on user machine first, and exported on token afterward:
```
dotnet run pkcs11-audit.cs -- --module "D:\SoftHSM2\lib\softhsm2-x64.dll" --pin 0000 --manufacturer softhsm --label mytoken --testing false --gen-keys-on-token false
```

By default, keys are generated on token.

Full commands list can be found in the --help menu:
```
  --module               Required. PKCS#11 .dll module for interaction with token

  --pin                  Required. PIN code for token operations

  --manufacturer         Required. Manufacturer ID of the token

  --label                Required. Label of the token

  --testing              Required. If true token is only tested, vulnerable key set is generated otherwise

  --gen-keys-on-token    Decides whether private keys should be generated on user side or on token side

  --rsa-size             Size of rsa key to be generated (2048 default)

  --wrap-type            Type of wrapping for sensitive keys; must be aes or rsa (aes default)

  --help                 Display this help screen.

  --version              Display version information.
```