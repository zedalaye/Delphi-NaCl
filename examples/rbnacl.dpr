program rbnacl;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils, libsodium, Sodium.Utils;

type
  ERbNaClSignature = class(Exception);

  TRbNaClSignatureEd25519VerifyKey = record
  strict private
    Key: TBytes;
  public
    constructor Create(const AKey: TBytes);

    function Verify(const Signature: TBytes; const Msg: string): Boolean;
    function VerifyAttached(const SignedMessage: TBytes): Boolean;
  end;

  TRbNaClSignatureEd25519SigningKey = record
  strict private
    Seed: TBytes;
    SigningKey: TBytes;
  public
    VerifyKey: TRbNaClSignatureEd25519VerifyKey;

    class function Primitive: string; static;
    class function SignatureBytes: Integer; static;

    class function Generate: TBytes; static;
    constructor Create(const ASeed: TBytes);

    function Sign(const Msg: string): TBytes;
    function SignAttached(const Msg: string): TBytes;

    function ToBytes: TBytes;
    function KeypairBytes: TBytes;

    function ToCurve25519PrivateKey: TBytes;
  end;

{ TRbNaClSignatureEd25519VerifyKey }

constructor TRbNaClSignatureEd25519VerifyKey.Create(const AKey: TBytes);
begin
  Key := AKey;
  if not Length(Key) = _CRYPTO_SIGN_ED25519_PUBLICKEYBYTES then
    raise ERbNaClSignature.CreateFmt('Key must be %d bytes long', [_CRYPTO_SIGN_ED25519_PUBLICKEYBYTES]);
end;

function TRbNaClSignatureEd25519VerifyKey.Verify(const Signature: TBytes;
  const Msg: string): Boolean;
var
  MsgBytes, Buffer: TBytes;
  BufLen: UInt64;
begin
  if not Length(Signature) = _CRYPTO_SIGN_ED25519_BYTES then
    raise ERbNaClSignature.CreateFmt('Signature must be %d bytes long', [_CRYPTO_SIGN_ED25519_BYTES]);

  MsgBytes := TEncoding.UTF8.GetBytes(Msg);
  BufLen := Length(MsgBytes) + _CRYPTO_SIGN_ED25519_BYTES;
  SetLength(Buffer, BufLen);
  Move(Signature[0], Buffer[0], Length(Signature));
  Move(MsgBytes[0], Buffer[_CRYPTO_SIGN_ED25519_BYTES], Length(MsgBytes));

  Result := VerifyAttached(Buffer);
end;

function TRbNaClSignatureEd25519VerifyKey.VerifyAttached(
  const SignedMessage: TBytes): Boolean;
var
  Buffer: TBytes;
  BufLen: UInt64;
begin
  if Length(SignedMessage) = 0 then
    raise ERbNaClSignature.Create('SignedMessage can''t be empty');

  if Length(SignedMessage) < _CRYPTO_SIGN_ED25519_BYTES then
    raise ERbNaClSignature.Create('SignedMessage can''t be shorter than a signature');

  SetLength(Buffer, Length(SignedMessage));
  TBytes.Zero(Buffer);
  BufLen := 0;

  Result := crypto_sign_ed25519_open(@Buffer[0], BufLen, @SignedMessage[0], Length(SignedMessage), @Key[0]) = 0;
end;

{ TRbNaClSignatureEd25519SigningKey }

class function TRbNaClSignatureEd25519SigningKey.Primitive: string;
begin
  Result := string(crypto_sign_primitive);
end;

class function TRbNaClSignatureEd25519SigningKey.SignatureBytes: Integer;
begin
  Result := _CRYPTO_SIGN_ED25519_BYTES;
end;

class function TRbNaClSignatureEd25519SigningKey.Generate: TBytes;
begin
  Result := TBytes.Random(_CRYPTO_SIGN_ED25519_SEEDBYTES);
end;

constructor TRbNaClSignatureEd25519SigningKey.Create(const ASeed: TBytes);
var
  PK, SK: TBytes;
begin
  if not Length(Seed) = _CRYPTO_SIGN_ED25519_SEEDBYTES then
    raise ERbNaClSignature.CreateFmt('Seed must be %d bytes long', [_CRYPTO_SIGN_ED25519_SEEDBYTES]);

  PK := TBytes.Zero(_CRYPTO_SIGN_ED25519_PUBLICKEYBYTES);
  SK := TBytes.Zero(_CRYPTO_SIGN_ED25519_SECRETKEYBYTES);

  if crypto_sign_ed25519_seed_keypair(@PK[0], @SK[0], @ASeed[0]) <> 0 then
    raise ERbNaClSignature.Create('Failed to generate a key pair');

  Seed := ASeed;
  SigningKey := SK;
  VerifyKey := TRbNaClSignatureEd25519VerifyKey.Create(PK);
end;

function TRbNaClSignatureEd25519SigningKey.KeypairBytes: TBytes;
begin
  Result := SigningKey;
end;

function TRbNaClSignatureEd25519SigningKey.Sign(const Msg: string): TBytes;
begin
  Result := Copy(SignAttached(Msg), 0, _CRYPTO_SIGN_ED25519_BYTES);
end;

function TRbNaClSignatureEd25519SigningKey.SignAttached(
  const Msg: string): TBytes;
var
  MsgBytes: TBytes;
  BufLen: UInt64;
begin
  MsgBytes := TEncoding.UTF8.GetBytes(Msg);
  BufLen := Length(MsgBytes) + _CRYPTO_SIGN_ED25519_BYTES;
  SetLength(Result, BufLen);
  Move(MsgBytes[0], Result[_CRYPTO_SIGN_ED25519_BYTES], Length(MsgBytes));
  crypto_sign_ed25519(@Result[0], BufLen, @MsgBytes[0], Length(MsgBytes), @SigningKey[0]);
end;

function TRbNaClSignatureEd25519SigningKey.ToBytes: TBytes;
begin
  Result := Seed;
end;

(*
  Return a new curve25519 (x25519) private key converted from this key

  it's recommeneded to read https://libsodium.gitbook.io/doc/advanced/ed25519-curve25519
  as it encourages using distinct keys for signing and for encryption
*)
function TRbNaClSignatureEd25519SigningKey.ToCurve25519PrivateKey: TBytes;
begin
  Result := TBytes.Zero(_CRYPTO_BOX_CURVE25519XSALSA20POLY1305_SECRETKEYBYTES);
  crypto_sign_ed25519_sk_to_curve25519(@Result[0], @SigningKey[0]);
end;

var
  Seed, SignatureAttached, Signature: TBytes;
  Sig: TRbNaClSignatureEd25519SigningKey;
begin
  try
    WriteLn(TRbNaClSignatureEd25519SigningKey.Primitive);
    WriteLn('SignatureBytes=', TRbNaClSignatureEd25519SigningKey.SignatureBytes);

    Seed := TRbNaClSignatureEd25519SigningKey.Generate;

    Sig := TRbNaClSignatureEd25519SigningKey.Create(Seed);
    SignatureAttached := Sig.SignAttached('Hello World');
    Signature := Sig.Sign('Hello World');

    if Sig.VerifyKey.Verify(Signature, 'Hello World') then
      WriteLn('OK')
    else
      WriteLn('Signature is corrupt');
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
