unit Sodium.OnetimeAuth;

interface

uses
  System.SysUtils,
  libsodium, Sodium.Utils;

type
  TCryptoOnetimeAuth = record
    class function Primitive: string; static;

    class function Keygen: TCryptoOnetimeAuthKey; static;

    class function Generate(var Tag: TCryptoOnetimeAuthTag; const &In: TBytes; const Key: TCryptoOnetimeAuthKey): Boolean; overload; static;
    class function Generate(var Tag: TCryptoOnetimeAuthTag; const InProc: TCryptoDataProc; const Key: TCryptoOnetimeAuthKey): Boolean; overload; static;

    class function Verify(const Tag: TCryptoOnetimeAuthTag; const &In: TBytes; const Key: TCryptoOnetimeAuthKey): Boolean; overload; static;
    class function Verify(const Tag: TCryptoOnetimeAuthTag; const InProc: TCryptoDataProc; const Key: TCryptoOnetimeAuthKey): Boolean; overload; static;
  end;

implementation

{ TCryptoOnetimeAuth }

class function TCryptoOnetimeAuth.Primitive: string;
begin
  Result := string(crypto_onetimeauth_primitive);
end;

class function TCryptoOnetimeAuth.Keygen: TCryptoOnetimeAuthKey;
begin
  crypto_onetimeauth_keygen(Result);
end;

class function TCryptoOnetimeAuth.Generate(var Tag: TCryptoOnetimeAuthTag;
  const &In: TBytes; const Key: TCryptoOnetimeAuthKey): Boolean;
begin
  Result := crypto_onetimeauth(@Tag[0], @&In[0], Length(&In), @Key[0]) = 0;
end;

class function TCryptoOnetimeAuth.Verify(const Tag: TCryptoOnetimeAuthTag;
  const &In: TBytes; const Key: TCryptoOnetimeAuthKey): Boolean;
begin
  Result := crypto_onetimeauth_verify(@Tag[0], @&In[0], Length(&In), @Key[0]) = 0;
end;

class function TCryptoOnetimeAuth.Generate(var Tag: TCryptoOnetimeAuthTag;
  const InProc: TCryptoDataProc; const Key: TCryptoOnetimeAuthKey): Boolean;
var
  State: TCryptoOnetimeAuthState;
  Done: Boolean;
  Buf: TBytes;
begin
  if crypto_onetimeauth_init(State, @Key[0]) <> 0 then
    Exit(False);

  Done := False;
  while not Done do
  begin
    InProc(Buf, Done);
    if crypto_onetimeauth_update(State, @Buf[0], Length(Buf)) <> 0 then
      Exit(False);
  end;

  Result := crypto_onetimeauth_final(State, @Tag[0]) = 0;
end;

class function TCryptoOnetimeAuth.Verify(const Tag: TCryptoOnetimeAuthTag;
  const InProc: TCryptoDataProc; const Key: TCryptoOnetimeAuthKey): Boolean;
var
  VerifyTag: TCryptoOnetimeAuthTag;
begin
  Result := False;
  if TCryptoOnetimeAuth.Generate(VerifyTag, InProc, Key) then
    Result := TBytes.Verify(Tag, VerifyTag, SizeOf(TCryptoOnetimeAuthTag));
end;

end.
