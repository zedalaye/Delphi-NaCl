program test_kdf;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
  libsodium in '..\lib\libsodium.pas',
  Sodium.Utils in '..\lib\Sodium.Utils.pas',
  Sodium.Kdf in '..\lib\Sodium.Kdf.pas';

procedure test_api(const MasterKey: TCryptoKdfKey; const Context: RawByteString);
var
  Ctx: TCryptoKdfContext;
  subkey_1: array[0..31] of Byte;
  subkey_2: array[0..31] of Byte;
  subkey_3: array[0..63] of Byte;
begin
  Move(Context[1], Ctx[0], Length(Context));

  WriteLn('master_key=', THexEncode.FromBytes(MasterKey, SizeOf(MasterKey)));

  crypto_kdf_derive_from_key(@subkey_1[0], SizeOf(subkey_1), 1, Ctx, MasterKey);
  WriteLn('subkey_1=',   THexEncode.FromBytes(@subkey_1[0], SizeOf(subkey_1)));

  crypto_kdf_derive_from_key(@subkey_2[0], SizeOf(subkey_2), 2, Ctx, MasterKey);
  WriteLn('subkey_2=',   THexEncode.FromBytes(@subkey_2[0], SizeOf(subkey_2)));

  crypto_kdf_derive_from_key(@subkey_3[0], SizeOf(subkey_3), 3, Ctx, MasterKey);
  WriteLn('subkey_3=',   THexEncode.FromBytes(@subkey_3[0], SizeOf(subkey_3)));
end;

procedure test(const MasterKey: TCryptoKdfKey; Context: TCryptoKdfContext);
const
  KeyLengths: array[0..2] of NativeUInt = (32, 32, 64);
var
  SubKeys: array[0..2] of TBytes;
  I: UInt64;
begin
  for I := Low(SubKeys) to High(SubKeys) do
    if not TCryptoKdf.DeriveFromKey(SubKeys[I], KeyLengths[I], I +1, Context, MasterKey) then
    begin
      WriteLn('FAILED');
      Exit;
    end;

  WriteLn('SUCCESS');
  for I := Low(SubKeys) to High(SubKeys) do
    WriteLn('SubKey', I+1, '=', THexEncode.FromBytes(SubKeys[I]));
end;

var
  MasterKey: TCryptoKdfKey;

begin
  try
    MasterKey := TCryptoKdf.Keygen;

    WriteLn('TCryptoKdf.Primitive=', TCryptoKdf.Primitive);
    Write('API...'); test_api(MasterKey, 'Examples');
    Write('Wrapper...'); test(MasterKey, 'Examples');
    
    ReadLn;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
