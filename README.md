# Delphi-NaCl

Delphi wrapper for (the awesome) [libsodium](https://github.com/jedisct1/libsodium)

`lib/libsodium.pas` import all functions and constants of libsodium

`lib/Sodium.*.pas` are Delphi Wrappers around the libsodium API meant to be used with managed Delphi types (`TBytes` in fact)

This wrapper is based on `libsodium` master branch (may be unstable), version `1.0.20`

Read the [libsodium documentation](https://libsodium.gitbook.io/doc/).

# Build libsodium for Windows using Visual Studio

These instructions are for Using Visual Studio 2022. Use start menu to open a "Developer Command Prompt for VS 2022"

```
C:\> git clone https://github.com/jedisct1/libsodium.git

# /!\ Build from master branch

C:\> cd libsodium\builds\msvc\vs2022
C:\> msbuild /m /v:n /p:Configuration=DynRelease /p:Platform=Win32 libsodium.sln
C:\> msbuild /m /v:n /p:Configuration=DynRelease /p:Platform=x64 libsodium.sln
```

Build artifacts can be found under `libsodium\bin\<Platform>\Release\v143\dynamic` with `<Platform>` being one of `Win32` or `x64`.

# Examples

Example code ported from `libsodium` documentation can be found under `examples` directory.

# License

This code is licensed under the same license as libsodium : [ISC License](https://en.wikipedia.org/wiki/ISC_license)
