unit Sodium.Kem;

interface

uses
  System.SysUtils,
  libsodium, Sodium.Utils;

type
  TCryptoKemPublicKey    = array[0.._CRYPTO_KEM_PUBLICKEYBYTES-1] of Byte;
  TCryptoKemSecretKey    = array[0.._CRYPTO_KEM_SECRETKEYBYTES-1] of Byte;
  TCryptoKemCipherText   = array[0.._CRYPTO_KEM_CIPHERTEXTBYTES-1] of Byte;
  TCryptoKemSharedSecret = array[0.._CRYPTO_KEM_SHAREDSECRETBYTES-1] of Byte;
  TCryptoKemSeed         = array[0.._CRYPTO_KEM_SEEDBYTES-1] of Byte;

  TCryptoKem = record
    class function Primitive: string; static;

    class function Keypair(var PublicKey: TCryptoKemPublicKey;
      var SecretKey: TCryptoKemSecretKey): Boolean; static;

    class function SeedKeypair(var PublicKey: TCryptoKemPublicKey;
      var SecretKey: TCryptoKemSecretKey; const Seed: TCryptoKemSeed): Boolean; static;

    class function Enc(var CipherText: TCryptoKemCipherText;
      var SharedSecret: TCryptoKemSharedSecret;
      const PublicKey: TCryptoKemPublicKey): Boolean; static;

    class function Dec(var SharedSecret: TCryptoKemSharedSecret;
      const CipherText: TCryptoKemCipherText;
      const SecretKey: TCryptoKemSecretKey): Boolean; static;
  end;

implementation

{ TCryptoKem }

class function TCryptoKem.Primitive: string;
begin
  Result := string(crypto_kem_primitive);
end;

class function TCryptoKem.Keypair(var PublicKey: TCryptoKemPublicKey;
  var SecretKey: TCryptoKemSecretKey): Boolean;
begin
  Result := crypto_kem_keypair(@PublicKey[0], @SecretKey[0]) = 0;
end;

class function TCryptoKem.SeedKeypair(var PublicKey: TCryptoKemPublicKey;
  var SecretKey: TCryptoKemSecretKey; const Seed: TCryptoKemSeed): Boolean;
begin
  Result := crypto_kem_seed_keypair(@PublicKey[0], @SecretKey[0], @Seed[0]) = 0;
end;

class function TCryptoKem.Enc(var CipherText: TCryptoKemCipherText;
  var SharedSecret: TCryptoKemSharedSecret;
  const PublicKey: TCryptoKemPublicKey): Boolean;
begin
  Result := crypto_kem_enc(@CipherText[0], @SharedSecret[0], @PublicKey[0]) = 0;
end;

class function TCryptoKem.Dec(var SharedSecret: TCryptoKemSharedSecret;
  const CipherText: TCryptoKemCipherText;
  const SecretKey: TCryptoKemSecretKey): Boolean;
begin
  Result := crypto_kem_dec(@SharedSecret[0], @CipherText[0], @SecretKey[0]) = 0;
end;

end.
