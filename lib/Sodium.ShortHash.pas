unit Sodium.ShortHash;

interface

uses
  System.SysUtils,
  libsodium, Sodium.Utils;

type
  TCryptoShortHash = record
    class function Primitive: string; static;

    class function Keygen: TCryptoShortHashKey; static;

    class function Generate(var Hash: TCryptoShortHashHash; const &In: TBytes; const Key: TCryptoShortHashKey): Boolean; static;
  end;

implementation

{ TCryptoShortHash }

class function TCryptoShortHash.Primitive: string;
begin
  Result := string(crypto_shorthash_primitive);
end;

class function TCryptoShortHash.Keygen: TCryptoShortHashKey;
begin
  crypto_shorthash_keygen(Result);
end;

class function TCryptoShortHash.Generate(var Hash: TCryptoShortHashHash;
  const &In: TBytes; const Key: TCryptoShortHashKey): Boolean;
begin
  Result := crypto_shorthash(@Hash[0], @&In[0], Length(&In), @Key[0]) = 0;
end;

end.
