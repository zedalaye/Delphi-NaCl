unit Sodium.ScalarMult;

interface

uses
  System.SysUtils,
  libsodium, Sodium.Utils;

type
  TCryptoScalarMult = record
    class function Primitive: string; static;

    class function Base(var Q; const N): Boolean; static;

    (*
     * NOTE: Do not use the result of this function directly for key exchange.
     *
     * Hash the result with the public keys in order to compute a shared
     * secret key: H(q || client_pk || server_pk)
     *
     * Or unless this is not an option, use the crypto_kx() API instead.
     *)
     class function Compute(var Q; const N; const P): Boolean; static;
  end;

implementation

{ TCryptoScalarMult }

class function TCryptoScalarMult.Primitive: string;
begin
  Result := string(crypto_scalarmult_primitive);
end;

class function TCryptoScalarMult.Base(var Q; const N): Boolean;
begin
  Result := crypto_scalarmult_base(@Q, @N) = 0;
end;

class function TCryptoScalarMult.Compute(var Q; const N; const P): Boolean;
begin
  Result := crypto_scalarmult(@Q, @N, @P) = 0;
end;

end.
