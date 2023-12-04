unit Sodium.Box;

interface

uses
  System.SysUtils,
  libsodium, Sodium.Utils;

type
  TCryptoBoxSeed      = libsodium.TCryptoBoxSeed;
  TCryptoBoxPublicKey = libsodium.TCryptoBoxPublicKey;
  TCryptoBoxSecretKey = libsodium.TCryptoBoxSecretKey;
  TCryptoBoxNonce     = libsodium.TCryptoBoxNonce;
  TCryptoBoxMac       = libsodium.TCryptoBoxMac;

  TCryptoBox = record
    class function Primitive: string; static;

    class function Keypair(var PublicKey: TCryptoBoxPublicKey; var SecretKey: TCryptoBoxSecretKey): Boolean; static;

    class function Nonce: TCryptoBoxNonce; static;

    class function Easy(
      var CipheredBuf: TBytes;
      ClearBuf: TBytes;
      Nonce: TCryptoBoxNonce;
      PublicKey: TCryptoBoxPublicKey; SecretKey: TCryptoBoxSecretKey): Boolean; static;

    class function OpenEasy(
      var ClearBuf: TBytes;
      CipheredBuf: TBytes;
      Nonce: TCryptoBoxNonce;
      PublicKey: TCryptoBoxPublicKey; SecretKey: TCryptoBoxSecretKey): Boolean; static;

    class function Detached(
      var CipheredBuf: TBytes; var AuthTag: TCryptoBoxMac;
      ClearBuf: TBytes;
      Nonce: TCryptoBoxNonce;
      PublicKey: TCryptoBoxPublicKey; SecretKey: TCryptoBoxSecretKey): Boolean; static;

    class function OpenDetached(
      var ClearBuf: TBytes;
      CipheredBuf: TBytes; AuthTag: TCryptoBoxMac;
      Nonce: TCryptoBoxNonce;
      PublicKey: TCryptoBoxPublicKey; SecretKey: TCryptoBoxSecretKey): Boolean; static;

    class function Seal(
      var CipheredBuf: TBytes;
      ClearBuf: TBytes;
      PublicKey: TCryptoBoxPublicKey): Boolean; static;

    class function OpenSeal(
      var ClearBuf: TBytes;
      CipheredBuf: TBytes;
      PublicKey: TCryptoBoxPublicKey; SecretKey: TCryptoBoxSecretKey): Boolean; static;
  end;

implementation

{ TCryptoBox }

class function TCryptoBox.Primitive: string;
begin
  Result := string(crypto_box_primitive);
end;

class function TCryptoBox.Keypair(var PublicKey: TCryptoBoxPublicKey;
  var SecretKey: TCryptoBoxSecretKey): Boolean;
begin
  Result := crypto_box_keypair(@PublicKey[0], @SecretKey[0]) = 0;
end;

class function TCryptoBox.Nonce: TCryptoBoxNonce;
begin
  randombytes_buf(@Result[0], SizeOf(Result));
end;

class function TCryptoBox.Easy(var CipheredBuf: TBytes; ClearBuf: TBytes;
  Nonce: TCryptoBoxNonce; PublicKey: TCryptoBoxPublicKey;
  SecretKey: TCryptoBoxSecretKey): Boolean;
begin
  SetLength(CipheredBuf, _CRYPTO_BOX_MACBYTES + Length(ClearBuf));
  Result := crypto_box_easy(@CipheredBuf[0], @ClearBuf[0], Length(ClearBuf),
              @Nonce[0], @PublicKey[0], @SecretKey[0]) = 0;
end;

class function TCryptoBox.OpenEasy(var ClearBuf: TBytes; CipheredBuf: TBytes;
  Nonce: TCryptoBoxNonce; PublicKey: TCryptoBoxPublicKey;
  SecretKey: TCryptoBoxSecretKey): Boolean;
begin
  SetLength(ClearBuf, Length(CipheredBuf) - _CRYPTO_BOX_MACBYTES);
  Result := crypto_box_open_easy(@ClearBuf[0], @CipheredBuf[0], Length(CipheredBuf),
              @Nonce[0], @PublicKey[0], @SecretKey[0]) = 0;
end;

class function TCryptoBox.Detached(var CipheredBuf: TBytes;
  var AuthTag: TCryptoBoxMac; ClearBuf: TBytes; Nonce: TCryptoBoxNonce;
  PublicKey: TCryptoBoxPublicKey; SecretKey: TCryptoBoxSecretKey): Boolean;
begin
  SetLength(CipheredBuf, Length(ClearBuf));
  Result := crypto_box_detached(@CipheredBuf[0], @AuthTag[0],
              @ClearBuf[0], Length(ClearBuf),
              @Nonce[0], @PublicKey[0], @SecretKey[0]) = 0;
end;

class function TCryptoBox.OpenDetached(var ClearBuf: TBytes;
  CipheredBuf: TBytes; AuthTag: TCryptoBoxMac; Nonce: TCryptoBoxNonce;
  PublicKey: TCryptoBoxPublicKey; SecretKey: TCryptoBoxSecretKey): Boolean;
begin
  SetLength(ClearBuf, Length(CipheredBuf));
  Result := crypto_box_open_detached(@ClearBuf[0], @CipheredBuf[0], @AuthTag[0], Length(CipheredBuf),
              @Nonce[0], @PublicKey[0], @SecretKey[0]) = 0;
end;

class function TCryptoBox.Seal(var CipheredBuf: TBytes; ClearBuf: TBytes;
  PublicKey: TCryptoBoxPublicKey): Boolean;
begin
  SetLength(CipheredBuf, Length(ClearBuf) + _CRYPTO_BOX_SEALBYTES);
  Result := crypto_box_seal(@CipheredBuf[0], @ClearBuf[0], Length(ClearBuf),
              @PublicKey[0]) = 0;
end;

class function TCryptoBox.OpenSeal(var ClearBuf: TBytes; CipheredBuf: TBytes;
  PublicKey: TCryptoBoxPublicKey; SecretKey: TCryptoBoxSecretKey): Boolean;
begin
  SetLength(ClearBuf, Length(CipheredBuf) - _CRYPTO_BOX_SEALBYTES);
  Result := crypto_box_seal_open(@ClearBuf[0], @CipheredBuf[0], Length(CipheredBuf),
              @PublicKey[0], @SecretKey[0]) = 0;
end;

end.
