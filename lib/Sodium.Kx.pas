unit Sodium.Kx;

interface

uses
  System.SysUtils,
  libsodium, Sodium.Utils;

type
  TCryptoKx = record
    class function Primitive: string; static;

    class function Keypair(var PublicKey: TCryptoKxPublicKey; var SecretKey: TCryptoKxSecretKey): Boolean; static;

    class function SeedKeypair(var PublicKey: TCryptoKxPublicKey; var SecretKey: TCryptoKxSecretKey;
      const Seed: TCryptoKxSeed): Boolean; static;

    class function ClientSessionKeys(var RxKey, TxKey: TCryptoKxSessionKey;
      const ClientPublicKey: TCryptoKxPublicKey; const ClientSecretKey: TCryptoKxSecretKey;
      const ServerPublicKey: TCryptoKxPublicKey): Boolean; static;

    class function ServerSessionKeys(var RxKey, TxKey: TCryptoKxSessionKey;
      const ServerPublicKey: TCryptoKxPublicKey; const ServerSecretKey: TCryptoKxSecretKey;
      const ClientPublicKey: TCryptoKxPublicKey): Boolean; static;
  end;

implementation

{ TCryptoKx }

class function TCryptoKx.Primitive: string;
begin
  Result := string(crypto_kx_primitive);
end;

class function TCryptoKx.Keypair(var PublicKey: TCryptoKxPublicKey;
  var SecretKey: TCryptoKxSecretKey): Boolean;
begin
  Result := crypto_kx_keypair(PublicKey, SecretKey) = 0;
end;

class function TCryptoKx.SeedKeypair(var PublicKey: TCryptoKxPublicKey;
  var SecretKey: TCryptoKxSecretKey; const Seed: TCryptoKxSeed): Boolean;
begin
  Result := crypto_kx_seed_keypair(PublicKey, SecretKey, Seed) = 0;
end;

class function TCryptoKx.ClientSessionKeys(var RxKey, TxKey: TCryptoKxSessionKey;
  const ClientPublicKey: TCryptoKxPublicKey; const ClientSecretKey: TCryptoKxSecretKey;
  const ServerPublicKey: TCryptoKxPublicKey): Boolean;
begin
  Result := crypto_kx_client_session_keys(
              RxKey, TxKey,
              ClientPublicKey, ClientSecretKey,
              ServerPublicKey) = 0;
end;

class function TCryptoKx.ServerSessionKeys(var RxKey,
  TxKey: TCryptoKxSessionKey; const ServerPublicKey: TCryptoKxPublicKey;
  const ServerSecretKey: TCryptoKxSecretKey;
  const ClientPublicKey: TCryptoKxPublicKey): Boolean;
begin
  Result := crypto_kx_server_session_keys(
              RxKey, TxKey,
              ServerPublicKey, ServerSecretKey,
              ClientPublicKey) = 0;
end;

end.
