unit Sodium.Sign;

interface

uses
  System.SysUtils,
  libsodium, Sodium.Utils;

type
  TCryptoSignSeed      = libsodium.TCryptoSignSeed;
  TCryptoSignPublicKey = libsodium.TCryptoSignPublicKey;
  TCryptoSignSecretKey = libsodium.TCryptoSignSecretKey;
  TCryptoSignature     = libsodium.TCryptoSignature;

  TCryptoScalarMultCurve25519Key = libsodium.TCryptoScalarMultCurve25519Key;

  TCryptoSign = record
    class function Primitive: string; static;

    class function Keypair(var PublicKey: TCryptoSignPublicKey; var SecretKey: TCryptoSignSecretKey): Boolean; static;
    class function SeedKeypair(var PublicKey: TCryptoSignPublicKey; var SecretKey: TCryptoSignSecretKey; const Seed): Boolean; static;

    class function SecretKeyToSeed(var Seed: TCryptoSignSeed; const SecretKey): Boolean; static;

    class function SecretKeyToPublicKey(var PublicKey: TCryptoSignPublicKey; const SecretKey): Boolean; static;

    class function PublicKeyToCurve25519(var Curve25519PublicKey: TCryptoScalarMultCurve25519Key; const PublicKey): Boolean; static;
    class function SecretKeyToCurve25519(var Curve25519SecretKey: TCryptoScalarMultCurve25519Key; const SecretKey): Boolean; static;

    class function Sign(var SignedBuf: TBytes; const ClearBuf: TBytes; const SecretKey): Boolean; static;
    class function OpenSign(var UnsignedBuf: TBytes; const SignedBuf: TBytes; const PublicKey): Boolean; static;

    class function Detached(var Signature: TCryptoSignature; const ClearBuf: TBytes; const SecretKey): Boolean; static;
    class function VerifyDetached(Signature: TCryptoSignature; const ClearBuf: TBytes; const PublicKey): Boolean; static;

    class function SignMultipart(var Signature: TCryptoSignature; const InProc: TCryptoDataProc; const SecretKey): Boolean; static;
    class function VerifyMutlipart(Signature: TCryptoSignature; const InProc: TCryptoDataProc; const PublicKey): Boolean; static;
  end;

implementation

{ TCryptoSign }

class function TCryptoSign.Primitive: string;
begin
  Result := string(crypto_sign_primitive);
end;

class function TCryptoSign.Keypair(var PublicKey: TCryptoSignPublicKey;
  var SecretKey: TCryptoSignSecretKey): Boolean;
begin
  Result := crypto_sign_keypair(@PublicKey[0], @SecretKey[0]) = 0;
end;

class function TCryptoSign.SeedKeypair(var PublicKey: TCryptoSignPublicKey;
  var SecretKey: TCryptoSignSecretKey; const Seed): Boolean;
begin
  Result := crypto_sign_seed_keypair(@PublicKey[0], @SecretKey[0], @Seed) = 0;
end;

class function TCryptoSign.SecretKeyToSeed(var Seed: TCryptoSignSeed;
  const SecretKey): Boolean;
begin
  Result := crypto_sign_ed25519_sk_to_seed(@Seed[0], @SecretKey) = 0;
end;

class function TCryptoSign.SecretKeyToPublicKey(
  var PublicKey: TCryptoSignPublicKey; const SecretKey): Boolean;
begin
  Result := crypto_sign_ed25519_sk_to_pk(@PublicKey[0], @SecretKey) = 0;
end;

class function TCryptoSign.PublicKeyToCurve25519(
  var Curve25519PublicKey: TCryptoScalarMultCurve25519Key;
  const PublicKey): Boolean;
begin
  Result := crypto_sign_ed25519_pk_to_curve25519(@Curve25519PublicKey[0], @PublicKey) = 0;
end;

class function TCryptoSign.SecretKeyToCurve25519(
  var Curve25519SecretKey: TCryptoScalarMultCurve25519Key;
  const SecretKey): Boolean;
begin
  Result := crypto_sign_ed25519_sk_to_curve25519(@Curve25519SecretKey[0], @SecretKey) = 0;
end;

class function TCryptoSign.Sign(var SignedBuf: TBytes; const ClearBuf: TBytes;
  const SecretKey): Boolean;
var
  SignedBufLen: UInt64;
begin
  SetLength(SignedBuf, Length(ClearBuf) + _CRYPTO_SIGN_BYTES);
  Result := crypto_sign(@SignedBuf[0], SignedBufLen, @ClearBuf[0], Length(ClearBuf), @SecretKey) = 0;
  SetLength(SignedBuf, SignedBufLen);
end;

class function TCryptoSign.OpenSign(var UnsignedBuf: TBytes;
  const SignedBuf: TBytes; const PublicKey): Boolean;
var
  UnsignedBufLen: UInt64;
begin
  SetLength(UnsignedBuf, Length(SignedBuf) - _CRYPTO_SIGN_BYTES);
  Result := crypto_sign_open(@UnsignedBuf[0], UnsignedBufLen,
              @SignedBuf[0], Length(SignedBuf), @PublicKey) = 0;
  SetLength(UnsignedBuf, UnsignedBufLen);
end;

class function TCryptoSign.Detached(var Signature: TCryptoSignature;
  const ClearBuf: TBytes; const SecretKey): Boolean;
var
  _SignatureLen: UInt64; // safe to ignore, Signature is always _CRYPTO_SIGN_BYTES long
begin
  Result := crypto_sign_detached(@Signature[0], _SignatureLen,
              @ClearBuf[0], Length(ClearBuf), @SecretKey) = 0;
end;

class function TCryptoSign.VerifyDetached(Signature: TCryptoSignature;
  const ClearBuf: TBytes; const PublicKey): Boolean;
begin
  Result := crypto_sign_verify_detached(@Signature[0],
              @ClearBuf[0], Length(ClearBuf), @PublicKey) = 0;
end;

class function TCryptoSign.SignMultipart(var Signature: TCryptoSignature;
  const InProc: TCryptoDataProc;
  const SecretKey): Boolean;
var
  State: TCryptoSignState;
  Done: Boolean;
  Buffer: TBytes;
  SignatureLen: UInt64;
begin
  if crypto_sign_init(State) <> 0 then
    Exit(False);

  Done := False;
  while not Done do
  begin
    InProc(Buffer, Done);
    if crypto_sign_update(State, @Buffer[0], Length(Buffer)) <> 0 then
      Exit(False);
  end;

  Result := crypto_sign_final_create(State,
              @Signature[0], SignatureLen, @SecretKey) = 0;
end;

class function TCryptoSign.VerifyMutlipart(Signature: TCryptoSignature;
  const InProc: TCryptoDataProc; const PublicKey): Boolean;
var
  State: TCryptoSignState;
  Done: Boolean;
  Buffer: TBytes;
begin
  if crypto_sign_init(State) <> 0 then
    Exit(False);

  Done := False;
  while not Done do
  begin
    InProc(Buffer, Done);
    if crypto_sign_update(State, @Buffer[0], Length(Buffer)) <> 0 then
      Exit(False);
  end;

  Result := crypto_sign_final_verify(State,
              @Signature[0], @PublicKey) = 0;
end;

end.
