unit Sodium.Aead;

interface

uses
  System.SysUtils,
  libsodium, Sodium.Utils;

type
  TCryptoAeadAegis128lKey = libsodium.TCryptoAeadAegis128lKey;
  TCryptoAeadAegis128lPubBytes = libsodium.TCryptoAeadAegis128lPubBytes;

  TCryptoAeadAegis128l = record
    class function Keygen: TCryptoAeadAegis128lKey; static;

    class function Encrypt(var CipheredText: TBytes;
                           const ClearText, AdditionalData: TBytes;
                           const Nonce: TCryptoAeadAegis128lPubBytes;
                           const Key: TCryptoAeadAegis128lKey): Boolean; overload; static;

    class function Decrypt(var DecipheredText: TBytes;
                           const CipheredText, AdditionalData: TBytes;
                           const Nonce: TCryptoAeadAegis128lPubBytes;
                           const Key: TCryptoAeadAegis128lKey): Boolean; overload; static;
  end;

  TCryptoAeadAegis256Key = libsodium.TCryptoAeadAegis256Key;
  TCryptoAeadAegis256PubBytes = libsodium.TCryptoAeadAegis256PubBytes;

  TCryptoAeadAegis256 = record
    class function Keygen: TCryptoAeadAegis256Key; static;

    class function Encrypt(var CipheredText: TBytes;
                           const ClearText, AdditionalData: TBytes;
                           const Nonce: TCryptoAeadAegis256PubBytes;
                           const Key: TCryptoAeadAegis256Key): Boolean; overload; static;

    class function Decrypt(var DecipheredText: TBytes;
                           const CipheredText, AdditionalData: TBytes;
                           const Nonce: TCryptoAeadAegis256PubBytes;
                           const Key: TCryptoAeadAegis256Key): Boolean; overload; static;
  end;

  TCryptoAeadChacha20poly1305IetfKey = libsodium.TCryptoAeadChacha20poly1305IetfKey;
  TCryptoAeadChacha20poly1305IetfPubBytes = libsodium.TCryptoAeadChacha20poly1305IetfPubBytes;

  TCryptoAeadChacha20poly1305Ietf = record
    class function Keygen: TCryptoAeadChacha20poly1305IetfKey; static;

    class function Encrypt(var CipheredText: TBytes;
                           const ClearText, AdditionalData: TBytes;
                           const Nonce: TCryptoAeadChacha20poly1305IetfPubBytes;
                           const Key: TCryptoAeadChacha20poly1305IetfKey): Boolean; overload; static;

    class function Decrypt(var DecipheredText: TBytes;
                           const CipheredText, AdditionalData: TBytes;
                           const Nonce: TCryptoAeadChacha20poly1305IetfPubBytes;
                           const Key: TCryptoAeadChacha20poly1305IetfKey): Boolean; overload; static;
  end;

  TCryptoAeadChacha20poly1305Key = libsodium.TCryptoAeadChacha20poly1305Key;
  TCryptoAeadChacha20poly1305PubBytes = libsodium.TCryptoAeadChacha20poly1305PubBytes;

  TCryptoAeadChacha20poly1305 = record
    class function Keygen: TCryptoAeadChacha20poly1305Key; static;

    class function Encrypt(var CipheredText: TBytes;
                           const ClearText, AdditionalData: TBytes;
                           const Nonce: TCryptoAeadChacha20poly1305PubBytes;
                           const Key: TCryptoAeadChacha20poly1305Key): Boolean; overload; static;

    class function Decrypt(var DecipheredText: TBytes;
                           const CipheredText, AdditionalData: TBytes;
                           const Nonce: TCryptoAeadChacha20poly1305PubBytes;
                           const Key: TCryptoAeadChacha20poly1305Key): Boolean; overload; static;
  end;

  TCryptoAeadXChacha20poly1305IetfKey= libsodium.TCryptoAeadXChacha20poly1305IetfKey;
  TCryptoAeadXChacha20poly1305IetfPubBytes = libsodium.TCryptoAeadXChacha20poly1305IetfPubBytes;

  TCryptoAeadXChacha20poly1305Ietf = record
    class function Keygen: TCryptoAeadXChacha20poly1305IetfKey; static;

    class function Encrypt(var CipheredText: TBytes;
                           const ClearText, AdditionalData: TBytes;
                           const Nonce: TCryptoAeadXChacha20poly1305IetfPubBytes;
                           const Key: TCryptoAeadXChacha20poly1305IetfKey): Boolean; overload; static;

    class function Decrypt(var DecipheredText: TBytes;
                           const CipheredText, AdditionalData: TBytes;
                           const Nonce: TCryptoAeadXChacha20poly1305IetfPubBytes;
                           const Key: TCryptoAeadXChacha20poly1305IetfKey): Boolean; overload; static;
  end;


implementation

{ TCryptoAeadAegis128l }

class function TCryptoAeadAegis128l.Keygen: TCryptoAeadAegis128lKey;
begin
  crypto_aead_aegis128l_keygen(Result);
end;

class function TCryptoAeadAegis128l.Encrypt(var CipheredText: TBytes;
  const ClearText, AdditionalData: TBytes;
  const Nonce: TCryptoAeadAegis128lPubBytes; const Key: TCryptoAeadAegis128lKey): Boolean;
var
  CipheredLen: UInt64;
begin
  SetLength(CipheredText, Length(ClearText) + _CRYPTO_AEAD_AEGIS128L_ABYTES);
  Result := crypto_aead_aegis128l_encrypt(@CipheredText[0], CipheredLen,
                                          @ClearText[0], Length(ClearText),
                                          BytesPointer(AdditionalData), Length(AdditionalData),
                                          nil, @Nonce[0], @Key[0]) = 0;
  SetLength(CipheredText, CipheredLen);
end;

class function TCryptoAeadAegis128l.Decrypt(var DecipheredText: TBytes;
  const CipheredText, AdditionalData: TBytes;
  const Nonce: TCryptoAeadAegis128lPubBytes;
  const Key: TCryptoAeadAegis128lKey): Boolean;
var
  DecipheredLen: UInt64;
begin
  SetLength(DecipheredText, Length(CipheredText));
  Result := crypto_aead_aegis128l_decrypt(@DecipheredText[0], DecipheredLen,
                                          nil,
                                          @CipheredText[0], Length(CipheredText),
                                          BytesPointer(AdditionalData), Length(AdditionalData),
                                          @Nonce[0], @Key[0]) = 0;
  SetLength(DecipheredText, DecipheredLen);
end;

{ TCryptoAeadAegis256 }

class function TCryptoAeadAegis256.Keygen: TCryptoAeadAegis256Key;
begin
  crypto_aead_aegis256_keygen(Result);
end;

class function TCryptoAeadAegis256.Encrypt(var CipheredText: TBytes;
  const ClearText, AdditionalData: TBytes;
  const Nonce: TCryptoAeadAegis256PubBytes;
  const Key: TCryptoAeadAegis256Key): Boolean;
var
  CipheredLen: UInt64;
begin
  SetLength(CipheredText, Length(ClearText) + _CRYPTO_AEAD_AEGIS256_ABYTES);
  Result := crypto_aead_aegis256_encrypt(@CipheredText[0], CipheredLen,
                                         @ClearText[0], Length(ClearText),
                                         BytesPointer(AdditionalData), Length(AdditionalData),
                                         nil, @Nonce[0], @Key[0]) = 0;
  SetLength(CipheredText, CipheredLen);
end;

class function TCryptoAeadAegis256.Decrypt(var DecipheredText: TBytes;
  const CipheredText, AdditionalData: TBytes;
  const Nonce: TCryptoAeadAegis256PubBytes;
  const Key: TCryptoAeadAegis256Key): Boolean;
var
  DecipheredLen: UInt64;
begin
  SetLength(DecipheredText, Length(CipheredText));
  Result := crypto_aead_aegis256_decrypt(@DecipheredText[0], DecipheredLen,
                                         nil,
                                         @CipheredText[0], Length(CipheredText),
                                         BytesPointer(AdditionalData), Length(AdditionalData),
                                         @Nonce[0], @Key[0]) = 0;
  SetLength(DecipheredText, DecipheredLen);
end;

{ TCryptoAeadChacha20poly1305Ietf }

class function TCryptoAeadChacha20poly1305Ietf.Keygen: TCryptoAeadChacha20poly1305IetfKey;
begin
  crypto_aead_chacha20poly1305_ietf_keygen(Result);
end;

class function TCryptoAeadChacha20poly1305Ietf.Encrypt(var CipheredText: TBytes;
  const ClearText, AdditionalData: TBytes;
  const Nonce: TCryptoAeadChacha20poly1305IetfPubBytes;
  const Key: TCryptoAeadChacha20poly1305IetfKey): Boolean;
var
  CipheredLen: UInt64;
begin
  SetLength(CipheredText, Length(ClearText) + _CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES);
  Result := crypto_aead_chacha20poly1305_ietf_encrypt(@CipheredText[0], CipheredLen,
                                                      @ClearText[0], Length(ClearText),
                                                      BytesPointer(AdditionalData), Length(AdditionalData),
                                                      nil, @Nonce[0], @Key[0]) = 0;
  SetLength(CipheredText, CipheredLen);
end;

class function TCryptoAeadChacha20poly1305Ietf.Decrypt(
  var DecipheredText: TBytes; const CipheredText, AdditionalData: TBytes;
  const Nonce: TCryptoAeadChacha20poly1305IetfPubBytes;
  const Key: TCryptoAeadChacha20poly1305IetfKey): Boolean;
var
  DecipheredLen: UInt64;
begin
  SetLength(DecipheredText, Length(CipheredText));
  Result := crypto_aead_chacha20poly1305_ietf_decrypt(@DecipheredText[0], DecipheredLen,
                                                      nil,
                                                      @CipheredText[0], Length(CipheredText),
                                                      BytesPointer(AdditionalData), Length(AdditionalData),
                                                      @Nonce[0], @Key[0]) = 0;
  SetLength(DecipheredText, DecipheredLen);
end;

{ TCryptoAeadChacha20poly1305 }

class function TCryptoAeadChacha20poly1305.Keygen: TCryptoAeadChacha20poly1305Key;
begin
  crypto_aead_chacha20poly1305_keygen(Result);
end;

class function TCryptoAeadChacha20poly1305.Encrypt(var CipheredText: TBytes;
  const ClearText, AdditionalData: TBytes;
  const Nonce: TCryptoAeadChacha20poly1305PubBytes;
  const Key: TCryptoAeadChacha20poly1305Key): Boolean;
var
  CipheredLen: UInt64;
begin
  SetLength(CipheredText, Length(ClearText) + _CRYPTO_AEAD_CHACHA20POLY1305_ABYTES);
  Result := crypto_aead_chacha20poly1305_encrypt(@CipheredText[0], CipheredLen,
                                                 @ClearText[0], Length(ClearText),
                                                 BytesPointer(AdditionalData), Length(AdditionalData),
                                                 nil, @Nonce[0], @Key[0]) = 0;
  SetLength(CipheredText, CipheredLen);
end;

class function TCryptoAeadChacha20poly1305.Decrypt(var DecipheredText: TBytes;
  const CipheredText, AdditionalData: TBytes;
  const Nonce: TCryptoAeadChacha20poly1305PubBytes;
  const Key: TCryptoAeadChacha20poly1305Key): Boolean;
var
  DecipheredLen: UInt64;
begin
  SetLength(DecipheredText, Length(CipheredText));
  Result := crypto_aead_chacha20poly1305_decrypt(@DecipheredText[0], DecipheredLen,
                                                 nil,
                                                 @CipheredText[0], Length(CipheredText),
                                                 BytesPointer(AdditionalData), Length(AdditionalData),
                                                 @Nonce[0], @Key[0]) = 0;
  SetLength(DecipheredText, DecipheredLen);
end;

{ TCryptoAeadXChacha20poly1305Ietf }

class function TCryptoAeadXChacha20poly1305Ietf.Keygen: TCryptoAeadXChacha20poly1305IetfKey;
begin
  crypto_aead_xchacha20poly1305_ietf_keygen(Result);
end;

class function TCryptoAeadXChacha20poly1305Ietf.Encrypt(var CipheredText: TBytes;
  const ClearText, AdditionalData: TBytes;
  const Nonce: TCryptoAeadXChacha20poly1305IetfPubBytes;
  const Key: TCryptoAeadXChacha20poly1305IetfKey): Boolean;
var
  CipheredLen: UInt64;
begin
  SetLength(CipheredText, Length(ClearText) + _CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES);
  Result := crypto_aead_xchacha20poly1305_ietf_encrypt(@CipheredText[0], CipheredLen,
                                                       @ClearText[0], Length(ClearText),
                                                       BytesPointer(AdditionalData), Length(AdditionalData),
                                                       nil, @Nonce[0], @Key[0]) = 0;
  SetLength(CipheredText, CipheredLen);
end;

class function TCryptoAeadXChacha20poly1305Ietf.Decrypt(var DecipheredText: TBytes;
  const CipheredText, AdditionalData: TBytes;
  const Nonce: TCryptoAeadXChacha20poly1305IetfPubBytes;
  const Key: TCryptoAeadXChacha20poly1305IetfKey): Boolean;
var
  DecipheredLen: UInt64;
begin
  SetLength(DecipheredText, Length(CipheredText));
  Result := crypto_aead_xchacha20poly1305_ietf_decrypt(@DecipheredText[0], DecipheredLen,
                                                       nil,
                                                       @CipheredText[0], Length(CipheredText),
                                                       BytesPointer(AdditionalData), Length(AdditionalData),
                                                       @Nonce[0], @Key[0]) = 0;
  SetLength(DecipheredText, DecipheredLen);
end;

end.
