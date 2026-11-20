# Cryptography Scripts
My personal repository of cryptography-related API examples, scripts, and maybe even pentest tools. Everything you see in this repo is for educational purposes only.

Basically, this is just a bunch of so-called "file-based apps" (dotnet), they can be launched using single console command. 

I chose dotnet because I mostly work with c# at this point of my life, and dotnet seems to be mature ecosystem with wide range of possibilities.

## PKCS#11 audit
A simple tool that checks private keys on pkcs11 devices for extractability. Supports two operational modes:

1. **Testing.** Generates private RSA-keys right on the device using weak configs (extractable = true).
```
dotnet run pkcs11-audit.cs -- --module "D:\SoftHSM2\lib\softhsm2-x64.dll" --pin 0000 --manufacturer softhsm --label mytoken --testing true
```

2. **Not testing.** Tries to extract private RSA-keys from the token, outputs them in PER-format if succeeds.
```
dotnet run pkcs11-audit.cs -- --module "D:\SoftHSM2\lib\softhsm2-x64.dll" --pin 0000 --manufacturer softhsm --label mytoken --testing false
```

