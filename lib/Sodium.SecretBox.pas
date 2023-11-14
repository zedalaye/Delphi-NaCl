unit Sodium.SecretBox;

interface

uses
  System.SysUtils,
  libsodium, Sodium.Utils;

type
  TCryptoSecretBox = record
    class function Primitive: string; static;

    class function Keygen: TCryptoSecretBoxKey; static;

    class function Easy(var CipherBuf: TBytes;
                        const ClearBuf: TBytes;
                        const Nonce: TCryptoSecretBoxNonce;
                        const Key: TCryptoSecretBoxKey): Boolean; static;

    class function OpenEasy(var ClearBuf: TBytes;
                            const CipherBuf: TBytes;
                            const Nonce: TCryptoSecretBoxNonce;
                            const Key: TCryptoSecretBoxKey): Boolean; static;

    class function Detached(var CipherBuf: TBytes; var Mac: TCryptoSecretBoxMac;
                            const ClearBuf: TBytes;
                            const Nonce: TCryptoSecretBoxNonce;
                            const Key: TCryptoSecretBoxKey): Boolean; static;

    class function OpenDetached(var ClearBuf: TBytes;
                                const CipherBuf: TBytes;
                                const Mac: TCryptoSecretBoxMac;
                                const Nonce: TCryptoSecretBoxNonce;
                                const Key: TCryptoSecretBoxKey): Boolean; static;
  end;

implementation

{ TCryptoSecretBox }

class function TCryptoSecretBox.Primitive: string;
begin
  Result := string(crypto_secretbox_primitive);
end;

class function TCryptoSecretBox.Keygen: TCryptoSecretBoxKey;
begin
  crypto_secretbox_keygen(Result);
end;

class function TCryptoSecretBox.Easy(var CipherBuf: TBytes;
  const ClearBuf: TBytes; const Nonce: TCryptoSecretBoxNonce;
  const Key: TCryptoSecretBoxKey): Boolean;
begin
  SetLength(CipherBuf, Length(ClearBuf) + _CRYPTO_SECRETBOX_MACBYTES);
  Result := crypto_secretbox_easy(@CipherBuf[0],
              @ClearBuf[0], Length(ClearBuf), @Nonce[0], @Key[0]) = 0;
end;

class function TCryptoSecretBox.OpenEasy(var ClearBuf: TBytes;
  const CipherBuf: TBytes; const Nonce: TCryptoSecretBoxNonce;
  const Key: TCryptoSecretBoxKey): Boolean;
begin
  SetLength(ClearBuf, Length(CipherBuf) - _CRYPTO_SECRETBOX_MACBYTES);
  Result := crypto_secretbox_open_easy(@ClearBuf[0],
              @CipherBuf[0], Length(CipherBuf), @Nonce[0], @Key[0]) = 0;
end;

class function TCryptoSecretBox.Detached(var CipherBuf: TBytes;
  var Mac: TCryptoSecretBoxMac; const ClearBuf: TBytes;
  const Nonce: TCryptoSecretBoxNonce; const Key: TCryptoSecretBoxKey): Boolean;
begin
  SetLength(CipherBuf, Length(ClearBuf));
  Result := crypto_secretbox_detached(@CipherBuf[0], @Mac[0],
              @ClearBuf[0], Length(ClearBuf), @Nonce[0], @Key[0]) = 0;
end;

class function TCryptoSecretBox.OpenDetached(var ClearBuf: TBytes;
  const CipherBuf: TBytes; const Mac: TCryptoSecretBoxMac;
  const Nonce: TCryptoSecretBoxNonce; const Key: TCryptoSecretBoxKey): Boolean;
begin
  SetLength(ClearBuf, Length(CipherBuf));
  Result := crypto_secretbox_open_detached(@ClearBuf[0],
              @CipherBuf[0], @Mac[0], Length(CipherBuf), @Nonce[0], @Key[0]) = 0;
end;

end.
