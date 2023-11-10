program SodiumTest;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  Winapi.Windows,
  System.SysUtils,
  System.NetEncoding,
  System.Hash,
  libsodium in '..\lib\libsodium.pas',
  Sodium.Utils in '..\lib\Sodium.Utils.pas';

procedure sha256_test;
var
  State: TCryptoHashSha256State;
  M1, M2: TBytes;
  &Out: TCryptoHashSha256Hash;
begin
  crypto_hash_sha256_init(State);

  M1 := TEncoding.UTF8.GetBytes('Arbitrary data to hash');
  crypto_hash_sha256_update(State, @M1[0], Length(M1));

  M2 := TEncoding.UTF8.GetBytes('is longer than expected');
  crypto_hash_sha256_update(State, @M2[0], Length(M2));

  crypto_hash_sha256_final(State, @&Out[0]);

  var Hex: TBytes;
  SetLength(Hex, SizeOf(&Out) *2 +1);
  sodium_bin2hex(@Hex[0], Length(Hex), @&Out[0], SizeOf(&Out));

  WriteLn('crypto_hash_sha256() => ', TEncoding.ASCII.GetString(Hex));

  WriteLn('System.Hash() => ', THashSHA2.GetHashString('Arbitrary data to hashis longer than expected'));
end;

procedure sha512_test;
var
  State: TCryptoHashSha512State;
  M1, M2: TBytes;
  &Out: TCryptoHashSha512Hash;
begin
  crypto_hash_sha512_init(State);

  M1 := TEncoding.UTF8.GetBytes('Arbitrary data to hash');
  crypto_hash_sha512_update(State, @M1[0], Length(M1));

  M2 := TEncoding.UTF8.GetBytes('is longer than expected');
  crypto_hash_sha512_update(State, @M2[0], Length(M2));

  crypto_hash_sha512_final(State, @&Out[0]);

  var Hex: TBytes;
  SetLength(Hex, SizeOf(&Out) *2 +1);
  sodium_bin2hex(@Hex[0], Length(Hex), @&Out[0], SizeOf(&Out));

  WriteLn('crypto_hash_sha512() => ', TEncoding.ASCII.GetString(Hex));

  WriteLn('System.Hash() => ', THashSHA2.GetHashString('Arbitrary data to hashis longer than expected', SHA512));
end;

procedure crypto_hash_test;
var
  &Out: TCryptoHashHash;
  &In: TBytes;
begin
  &In := TEncoding.UTF8.GetBytes('Arbitrary data to hashis longer than expected');

  crypto_hash(@&Out[0], @&In[0], Length(&In));

  var Hex: TBytes;
  SetLength(Hex, SizeOf(&Out) *2 +1);
  sodium_bin2hex(@Hex[0], Length(Hex), @&Out[0], SizeOf(&Out));

  WriteLn('crypto_hash() => ', TEncoding.ASCII.GetString(Hex));
end;

procedure generic_hash_test;
var
  StateP: Pointer;
  State: PCryptoGenericHashState;
  &Out: TCryptoGenericHash;
  &In: TBytes;
  Key: TCryptoGenericHashKey;
begin
  WriteLn('crypto_generichash_statebytes() => ', crypto_generichash_statebytes);
  WriteLn('SizeOf(TCryptoGenericHashState) => ', SizeOf(TCryptoGenericHashState));

  sodium_memzero(@Key[0], SizeOf(Key));
//  randombytes_buf(@Key[0], SizeOf(Key));

  &In := TEncoding.UTF8.GetBytes('Arbitrary data to hash');
  crypto_generichash(@&Out[0], SizeOf(&Out), @&In[0], Length(&In), @Key[0], SizeOf(Key));

  var Hex: TBytes;
  SetLength(Hex, SizeOf(&Out) *2 +1);
  sodium_bin2hex(@Hex[0], Length(Hex), @&Out[0], SizeOf(&Out));

  WriteLn('crypto_generichash() => ', TEncoding.ASCII.GetString(Hex));

  State := GetAlignedCryptoGenericHashState(StateP);

  crypto_generichash_init(State^, @Key[0], SizeOf(Key), SizeOf(&Out));
  crypto_generichash_update(State^, @&In[0], Length(&In));
  crypto_generichash_final(State^, @&Out[0], SizeOf(&Out));

  sodium_memzero(@Hex[0], Length(Hex));
  sodium_bin2hex(@Hex[0], Length(Hex), @&Out[0], SizeOf(&Out));
  WriteLn('crypto_generichash() => ', TEncoding.ASCII.GetString(Hex));

  FreeMem(StateP);
end;

procedure align_test;
var
  AR: TCryptoGenericHashState;
  PA: PCryptoGenericHashState;
  PAA: array[0..99] of Pointer;
begin
  WriteLn(Format('AR=%p, @AR mod 64 = %d', [@AR, NativeUInt(@AR) mod 64]), ', SizeOf(AR)=', SizeOf(AR));

  for var I := 0 to High(PAA) do
  begin
    GetMem(PA, SizeOf(PA) + 63);
    var HighPA := NativeUInt(PA) + SizeOf(PA) + 63;
    PAA[I] := PA;
    PA := PCryptoGenericHashState((Integer(PA) + 63) and not(63));
    WriteLn(Format('PA=%p, Offset=%2d, @PA mod 64 = %d', [PA, NativeUInt(PA) - NativeUInt(PAA[I]), NativeUInt(PA) mod 64]), ', SizeOf(PA)=', SizeOf(PA^));
    Assert(NativeUInt(PA) + SizeOf(PA) < HighPA);
  end;

  for var I := High(PAA) downto 0 do
    FreeMem(PAA[I]);
end;

procedure hmac_sha512_test;
var
  &Out: TCryptoAuthHmacSha512Hash;
  Key: TCryptoAuthHmacSha512Key;
  M: TBytes;
begin
  M := TEncoding.UTF8.GetBytes('Arbitrary data to hash');

  crypto_auth_hmacsha512_keygen(Key);
  crypto_auth_hmacsha512(@&Out[0], @M[0], Length(M), @Key[0]);

  var Hex: TBytes;
  SetLength(Hex, SizeOf(&Out) *2 +1);
  sodium_bin2hex(@Hex[0], Length(Hex), @&Out[0], SizeOf(&Out));

  WriteLn('crypto_auth_hmacsha512() => ', TEncoding.ASCII.GetString(Hex));
end;

procedure hmac_sha256_test;
var
  &Out: TCryptoAuthHmacSha256Hash;
  Key: TCryptoAuthHmacSha256Key;
  M: TBytes;
begin
  M := TEncoding.UTF8.GetBytes('Arbitrary data to hash');

  crypto_auth_hmacsha256_keygen(Key);
  crypto_auth_hmacsha256(@&Out[0], @M[0], Length(M), @Key[0]);

  var Hex: TBytes;
  SetLength(Hex, SizeOf(&Out) *2 +1);
  sodium_bin2hex(@Hex[0], Length(Hex), @&Out[0], SizeOf(&Out));

  WriteLn('crypto_auth_hmacsha256() => ', TEncoding.ASCII.GetString(Hex));
end;

procedure hmac_sha512256_test;
var
  &Out: TCryptoAuthHmacSha512256Hash;
  Key: TCryptoAuthHmacSha512256Key;
  M: TBytes;
begin
  M := TEncoding.UTF8.GetBytes('Arbitrary data to hash');

  crypto_auth_hmacsha512256_keygen(Key);
  crypto_auth_hmacsha512256(@&Out[0], @M[0], Length(M), @Key[0]);

  var Hex: TBytes;
  SetLength(Hex, SizeOf(&Out) *2 +1);
  sodium_bin2hex(@Hex[0], Length(Hex), @&Out[0], SizeOf(&Out));

  WriteLn('crypto_auth_hmacsha512256() => ', TEncoding.ASCII.GetString(Hex));
end;

procedure crypto_auth_test;
var
  Key: TCryptoAuthKey;
  Mac: TCryptoAuthHash;
  M: TBytes;
begin
  crypto_auth_keygen(Key);

  M := TEncoding.UTF8.GetBytes('test');
  crypto_auth(@Mac[0], @M[0], Length(M), @Key[0]);
  var ret := crypto_auth_verify(@Mac[0], @M[0], Length(M), @Key[0]);

  WriteLn('crypto_auth() => ', ret);
end;

procedure crypto_box_test;
var
  alice_pk: TCryptoBoxPublicKey;
  alice_sk: TCryptoBoxSecretKey;
  bob_pk: TCryptoBoxPublicKey;
  bob_sk: TCryptoBoxSecretKey;
  nonce: TCryptoBoxNonce;
  ciphertext: TBytes;
  decrypted: TBytes;
begin
  crypto_box_keypair(@alice_pk[0], @alice_sk[0]);
  crypto_box_keypair(@bob_pk[0], @bob_sk[0]);

  randombytes_buf(@nonce[0], SizeOf(nonce));

  var M := TEncoding.UTF8.GetBytes('test');
  SetLength(ciphertext, _CRYPTO_BOX_MACBYTES + Length(M));

  if crypto_box_easy(@ciphertext[0], @M[0], Length(M), @nonce[0], @bob_pk[0], @alice_sk[0]) <> 0 then
  begin
    WriteLn('crypto_box_easy() => FAILED');
    Exit;
  end;

  SetLength(decrypted, Length(M));
  if crypto_box_open_easy(@decrypted[0], @ciphertext[0], Length(ciphertext), @nonce[0], @alice_pk[0], @bob_sk[0]) <> 0 then
    WriteLn('crypto_box_open_easy() => FAILED')
  else
    WriteLn('crypto_box() => OK');
end;

procedure crypto_kdf_test;
const
  CONTEXT: RawByteString = 'CONTEXT';
var
  master_key: TCryptoKdfKey;
  ctx: TCryptoKdfContext;
  subkey_1: array[0..31] of Byte;
  subkey_2: array[0..31] of Byte;
  subkey_3: array[0..63] of Byte;
begin
  Move(CONTEXT[1], ctx[0], SizeOf(ctx));

  crypto_kdf_keygen(master_key);

  crypto_kdf_derive_from_key(@subkey_1[0], SizeOf(subkey_1), 1, ctx, master_key);
  crypto_kdf_derive_from_key(@subkey_2[0], SizeOf(subkey_2), 2, ctx, master_key);
  crypto_kdf_derive_from_key(@subkey_3[0], SizeOf(subkey_3), 3, ctx, master_key);

  WriteLn('master_key=', HexEncode(@master_key[0], SizeOf(master_key)));
  WriteLn('subkey_1=', HexEncode(@subkey_1[0], SizeOf(subkey_1)));
  WriteLn('subkey_2=', HexEncode(@subkey_2[0], SizeOf(subkey_2)));
  WriteLn('subkey_3=', HexEncode(@subkey_3[0], SizeOf(subkey_3)));
end;

procedure crypto_kx_test;
var
  client_pk: TCryptoKxPublicKey;
  client_sk: TCryptoKxSecretKey;
  client_rx: TCryptoKxSessionKey;
  client_tx: TCryptoKxSessionKey;

  server_pk: TCryptoKxPublicKey;
  server_sk: TCryptoKxSecretKey;
  server_rx: TCryptoKxSessionKey;
  server_tx: TCryptoKxSessionKey;
begin
  crypto_kx_keypair(client_pk, client_sk);
  crypto_kx_keypair(server_pk, server_sk);

  if crypto_kx_client_session_keys(client_rx, client_tx, client_pk, client_sk, server_pk) <> 0 then
  begin
    WriteLn('crypto_kx_client_session_keys() => FAILED');
    Exit;
  end;

  if crypto_kx_server_session_keys(server_rx, server_tx, server_pk, server_sk, client_pk) <> 0 then
  begin
    WriteLn('crypto_kx_server_session_keys() => FAILED');
    Exit;
  end;

  WriteLn('client_pk=', HexEncode(@client_pk[0], SizeOf(client_pk)));
  WriteLn('client_sk=', HexEncode(@client_sk[0], SizeOf(client_sk)));
  WriteLn('client_rx=', HexEncode(@client_rx[0], SizeOf(client_rx)));
  WriteLn('client_tx=', HexEncode(@client_tx[0], SizeOf(client_tx)));

  WriteLn('server_pk=', HexEncode(@server_pk[0], SizeOf(server_pk)));
  WriteLn('server_sk=', HexEncode(@server_sk[0], SizeOf(server_sk)));
  WriteLn('server_rx=', HexEncode(@server_rx[0], SizeOf(server_rx)));
  WriteLn('server_tx=', HexEncode(@server_tx[0], SizeOf(server_tx)));
end;

procedure crypto_onetimeauth_test;
var
  &out: TCryptoOnetimeAuth;
  key: TCryptoOnetimeAuthKey;
begin
  var M := TEncoding.UTF8.GetBytes('Data to authenticate');

  crypto_onetimeauth_keygen(key);

  if crypto_onetimeauth(@&out[0], @M[0], Length(M), @key[0]) = 0 then
  begin
    WriteLn('crypto_onetimeauth() => ', HexEncode(@&out[0], SizeOf(&out)));

    if crypto_onetimeauth_verify(@&out[0], @M[0], Length(M), @key[0]) = 0 then
      WriteLn('crypto_onetimeauth_verify() => SUCCESS')
    else
      WriteLn('crypto_onetimeauth_verify() => FAILED')
  end
  else
    WriteLn('crypto_onetimeauth() => FAILED');
end;

procedure crypto_pwhash_test;
var
  salt: TCryptoPwHashSalt;
  key: TCryptoBoxSeed;
  hashed_password: TCryptoPwHashStr;
begin
  randombytes_buf(@salt[0], SizeOf(salt));

  var P := TEncoding.UTF8.GetBytes('Correct Horse Battery Staple');

  if crypto_pwhash(@key[0], SizeOf(key),
                   PAnsiChar(P), Length(P),
                   @salt[0],
                   _CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE, _CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
                   _CRYPTO_PWHASH_ALG_DEFAULT) <> 0 then
    WriteLn('crypto_pwhash() => FAILED')
  else
    WriteLn('crypto_pwhash() => SUCCESS key = ', HexEncode(@key[0], SizeOf(key)));

  if crypto_pwhash_str(hashed_password,
                       PAnsiChar(P), Length(P),
                       _CRYPTO_PWHASH_OPSLIMIT_SENSITIVE, _CRYPTO_PWHASH_MEMLIMIT_SENSITIVE) <> 0 then
    WriteLn('crypto_pwhash_str() => FAILED')
  else
  begin
    WriteLn('crypto_pwhash_str() => SUCCESS');
    WriteLn('hashed_password = ', string(hashed_password));

    if crypto_pwhash_str_verify(hashed_password, PAnsiChar(P), Length(P)) <> 0 then
      WriteLn('crypto_pwhash_str_verify() => FAILED')
    else
      WriteLn('crypto_pwhash_str_verify() => SUCCESS')
  end;
end;

procedure crypto_scalarmult_test;
var
  client_pk: TCryptoBoxPublicKey;
  client_sk: TCryptoBoxSecretKey;
  server_pk: TCryptoBoxPublicKey;
  server_sk: TCryptoBoxSecretKey;
  scalarmult_q_by_client: TCryptoScalarMultQ;
  scalarmult_q_by_server: TCryptoScalarMultQ;
  sharedkey_by_client: TCryptoGenericHash;
  sharedkey_by_server: TCryptoGenericHash;
  h: TCryptoGenericHashState;
begin
  (* Create client's secret and public keys *)
  randombytes_buf(@client_sk[0], SizeOf(client_sk));
  crypto_scalarmult_base(@client_pk[0], @client_sk[0]);

  (* Create server's secret and public keys *)
  randombytes_buf(@server_sk[0], SizeOf(server_sk));
  crypto_scalarmult_base(@server_pk[0], @server_sk[0]);

  (* The client derives a shared key from its secret key and the server's public key *)
  (* shared key = h(q ‖ client_publickey ‖ server_publickey) *)

  if crypto_scalarmult(@scalarmult_q_by_client[0], @client_sk[0], @server_pk[0]) <> 0 then
  begin
    WriteLn('crypto_scalarmult(q_by_client) => FAILED');
    Exit;
  end;

  WriteLn('crypto_scalarmult(q_by_client) = ', HexEncode(@scalarmult_q_by_client[0], SizeOf(scalarmult_q_by_client)));

  crypto_generichash_init(h, nil, 0, SizeOf(sharedkey_by_client));
  crypto_generichash_update(h, @scalarmult_q_by_client[0], SizeOf(scalarmult_q_by_client));
  crypto_generichash_update(h, @client_pk[0], SizeOf(client_pk));
  crypto_generichash_update(h, @server_pk[0], SizeOf(server_pk));
  crypto_generichash_final(h, @sharedkey_by_client[0], SizeOf(sharedkey_by_client));

  WriteLn('sharedkey_by_client = ', HexEncode(@sharedkey_by_client[0], SizeOf(sharedkey_by_client)));

  (* The server derives a shared key from its secret key and the client's public key *)
  (* shared key = h(q ‖ client_publickey ‖ server_publickey) *)
  if crypto_scalarmult(@scalarmult_q_by_server[0], @server_sk[0], @client_pk[0]) <> 0 then
  begin
    WriteLn('crypto_scalarmult(q_by_server) => FAILED');
    Exit;
  end;
  WriteLn('crypto_scalarmult(q_by_server) = ', HexEncode(@scalarmult_q_by_server[0], SizeOf(scalarmult_q_by_server)));
  crypto_generichash_init(h, nil, 0, SizeOf(sharedkey_by_server));
  crypto_generichash_update(h, @scalarmult_q_by_server[0], SizeOf(scalarmult_q_by_server));
  crypto_generichash_update(h, @client_pk[0], SizeOf(client_pk));
  crypto_generichash_update(h, @server_pk[0], SizeOf(server_pk));
  crypto_generichash_final(h, @sharedkey_by_server[0], SizeOf(sharedkey_by_server));
  WriteLn('sharedkey_by_server = ', HexEncode(@sharedkey_by_server[0], SizeOf(sharedkey_by_server)));
  (* sharedkey_by_client and sharedkey_by_server are identical *)

  if sodium_memcmp(@sharedkey_by_client[0], @sharedkey_by_server[0], SizeOf(TCryptoGenericHash)) <> 0 then
    WriteLn('crypto_scalarmult() generation of shared key => FAILED')
  else
    WriteLn('crypto_scalarmult() generation of shared key => SUCCESS')
end;

procedure crypto_secretbox_test;
var
  key: TCryptoSecretBoxKey;
  nonce: TCryptoSecretBoxNonce;
  ciphertext: TBytes;
  decrypted: TBytes;
begin
  var M := TEncoding.UTF8.GetBytes('test');
  SetLength(ciphertext, _CRYPTO_SECRETBOX_MACBYTES + Length(M));

  crypto_secretbox_keygen(key);
  randombytes_buf(@nonce[0], SizeOf(nonce));

  crypto_secretbox_easy(@ciphertext[0], @M[0], Length(M), @nonce[0], @key[0]);

  SetLength(decrypted, Length(M));
  if crypto_secretbox_open_easy(@decrypted[0], @ciphertext[0], Length(ciphertext), @nonce[0], @key[0]) <> 0 then
    WriteLn('crypto_secretbox() => FAILED')
  else
    WriteLn('crypto_secretbox() => SUCCESS');
end;

procedure crypto_secret_stream_test;
var
  state: TCryptoSecretStreamXChacha20Poly1305State;
  key: TCryptoSecretStreamXChacha20Poly1305Key;
  header: TCryptoSecretStreamXChacha20Poly1305Header;
  tag: Byte;
begin
  var M1 := TEncoding.UTF8.GetBytes('Arbitrary data to encrypt');
  var M2 := TEncoding.UTF8.GetBytes('split into');
  var M3 := TEncoding.UTF8.GetBytes('three messages');

  (* Shared secret key required to encrypt/decrypt the stream *)
  crypto_secretstream_xchacha20poly1305_keygen(key);
  (* Set up a new stream: initialize the state and create the header *)
  crypto_secretstream_xchacha20poly1305_init_push(state, header, key);
  (* Now, encrypt the first chunk. `c1` will contain an encrypted,
   * authenticated representation of `MESSAGE_PART1`. *)
  var C1: TBytes; var C1L: UInt64;
  SetLength(C1, Length(M1) + _CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES);
  crypto_secretstream_xchacha20poly1305_push(state, @C1[0], C1L, @M1[0], Length(M1), nil, 0, 0);
  (* Encrypt the second chunk. `c2` will contain an encrypted, authenticated
   * representation of `MESSAGE_PART2`. *)
  var C2: TBytes; var C2L: UInt64;
  SetLength(C2, Length(M2) + _CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES);
  crypto_secretstream_xchacha20poly1305_push(state, @C2[0], C2L, @M2[0], Length(M2), nil, 0, 0);
  (* Encrypt the last chunk, and store the ciphertext into `c3`.
   * Note the `TAG_FINAL` tag to indicate that this is the final chunk. *)
  var C3: TBytes; var C3L: UInt64;
  SetLength(C3, Length(M3) + _CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES);
  crypto_secretstream_xchacha20poly1305_push(state, @C3[0], C3L, @M3[0], Length(M3), nil, 0,
    _CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL);

  (* Decrypt the stream: initializes the state, using the key and a header *)
  if (crypto_secretstream_xchacha20poly1305_init_pull(state, header, key) <> 0) then
  begin
    WriteLn('crypto_secretstream_xchacha20poly1305_init_pull() => Invalid Header');
    Exit;
  end;
  (* Decrypt the first chunk. A real application would probably use
   * a loop, that reads data from the network or from disk, and exits after
   * an error, or after the last chunk (with a `TAG_FINAL` tag) has been
   * decrypted. *)
  var D1: TBytes; var D1L: UInt64;
  SetLength(D1, Length(M1));
  if (crypto_secretstream_xchacha20poly1305_pull(state, @D1[0], D1L, tag, @C1[0], Length(C1), nil, 0) <> 0) then
  begin
    WriteLn('crypto_secretstream_xchacha20poly1305_pull(C1) => Invalid CipherText');
    Exit;
  end;
  Assert(tag = 0); (* The tag is the one we attached to this chunk: 0 *)
  (* Decrypt the second chunk, store the result into `m2` *)
  var D2: TBytes; var D2L: UInt64;
  SetLength(D2, Length(M2));
  if (crypto_secretstream_xchacha20poly1305_pull(state, @D2[0], D2L, tag, @C2[0], Length(C2), nil, 0) <> 0) then
  begin
    WriteLn('crypto_secretstream_xchacha20poly1305_pull(C2) => Invalid CipherText');
    Exit;
  end;
  Assert(tag = 0); (* Not the end of the stream yet *)
  (* Decrypt the last chunk, store the result into `m3` *)
  var D3: TBytes; var D3L: UInt64;
  SetLength(D3, Length(M3));
  if (crypto_secretstream_xchacha20poly1305_pull(state, @D3[0], D3L, tag, @C3[0], Length(C3), nil, 0) <> 0) then
  begin
    WriteLn('crypto_secretstream_xchacha20poly1305_pull(C3) => Invalid CipherText');
    Exit;
  end;
  (* The tag indicates that this is the final chunk, no need to read and decrypt more *)
  Assert(tag = _CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL);

  WriteLn('crypto_secret_stream => SUCCESS');
end;

procedure crypto_short_hash_test;
var
  hash: TCryptoShortHash;
  key: TCryptoShortHashKey;
begin
  var ShortData := TEncoding.UTF8.GetBytes('Sparkling water');

  crypto_shorthash_keygen(key);
  if crypto_shorthash(@hash[0], @ShortData[0], Length(ShortData), @key[0]) = 0 then
    WriteLn('crypto_shorthash() = ', HexEncode(@hash[0], SizeOf(hash)))
  else
    WriteLn('crypto_shorthash() => FAILED');
end;

procedure crypto_sign_test;
var
  pk: TCryptoSignPublicKey;
  sk: TCryptoSignSecretKey;
  sig: TCryptoSign;
begin
  var M := TEncoding.UTF8.GetBytes('test');

  crypto_sign_keypair(@pk[0], @sk[0]);

  var signed_message: TBytes; var signed_message_len: UInt64;
  SetLength(signed_message, Length(M) + _CRYPTO_SIGN_BYTES);

  crypto_sign(@signed_message[0], signed_message_len, @M[0], Length(M), @sk[0]);

  WriteLn('crypto_sign() => ', HexEncode(@signed_message[0], signed_message_len));

  var unsigned_message: TBytes; var unsigned_message_len: UInt64;
  SetLength(unsigned_message, Length(M));

  if crypto_sign_open(@unsigned_message[0], unsigned_message_len, @signed_message[0], signed_message_len, @pk[0]) <> 0 then
    WriteLn('crypto_sign_open() => FAILED')
  else
    WriteLn('crypto_sign_open() => SUCCESS');

  var sig_len: UInt64;
  crypto_sign_detached(@sig[0], sig_len, @M[0], Length(M), @sk[0]);

  WriteLn('crypto_sign_detached() => ', HexEncode(@sig[0], sig_len));

  if crypto_sign_verify_detached(@sig[0], @M[0], Length(M), @pk[0]) <> 0 then
    WriteLn('crypto_sign_verify_detached() => FAILED')
  else
    WriteLn('crypto_sign_verify_detached() => SUCCESS');
end;

var
  ret: Integer;

procedure sodium_misuse_handler; cdecl;
begin
  WriteLn('Misuse');
end;

begin
  try
    ret := sodium_init;
    WriteLn('sodium_init() => ', ret);

    WriteLn('sodium_version_string() => ',        string(UTF8String(sodium_version_string)));
    WriteLn('sodium_library_version_major() => ', sodium_library_version_major);
    WriteLn('sodium_library_version_minor() => ', sodium_library_version_minor);
    WriteLn('sodium_library_minimal() => ',       sodium_library_minimal);

    ret := sodium_set_misuse_handler(sodium_misuse_handler);
    WriteLn('sodium_set_misuse_handler() => ', ret);

    WriteLn('sodium_base64_ENCODED_LEN(100, 1) => theirs=', sodium_base64_ENCODED_LEN(100, 1), ', mine=', _SODIUM_BASE64_ENCODED_LEN(100, 1));
    WriteLn('sodium_base64_ENCODED_LEN(100, 3) => theirs=', sodium_base64_ENCODED_LEN(100, 3), ', mine=', _SODIUM_BASE64_ENCODED_LEN(100, 3));
    WriteLn('sodium_base64_ENCODED_LEN(100, 5) => theirs=', sodium_base64_ENCODED_LEN(100, 5), ', mine=', _SODIUM_BASE64_ENCODED_LEN(100, 5));
    WriteLn('sodium_base64_ENCODED_LEN(100, 7) => theirs=', sodium_base64_ENCODED_LEN(100, 7), ', mine=', _SODIUM_BASE64_ENCODED_LEN(100, 7));

    var Buf: TBytes;
    SetLength(Buf, 20);
    for var I := Low(Buf) to High(Buf) do
      Buf[I] := Random(256);

    var Hex: AnsiString;
    SetLength(Hex, Length(Buf) * 2 + 1);
    sodium_bin2hex(PAnsiChar(Hex), Length(Hex), @Buf[0], Length(Buf));
    WriteLn('sodium_bin2hex() => ', Hex);

    var B64: AnsiString;
    SetLength(B64, _SODIUM_BASE64_ENCODED_LEN(Length(Buf), 1));
    sodium_bin2base64(PAnsiChar(B64), Length(B64), @Buf[0], Length(Buf), sodium_base64_VARIANT_ORIGINAL);
    WriteLn('sodium_bin2base64(1) => ', string(B64));
    SetLength(B64, _SODIUM_BASE64_ENCODED_LEN(Length(Buf), 3));
    sodium_bin2base64(PAnsiChar(B64), Length(B64), @Buf[0], Length(Buf), sodium_base64_VARIANT_ORIGINAL_NO_PADDING);
    WriteLn('sodium_bin2base64(3) => ', string(B64));
    SetLength(B64, _SODIUM_BASE64_ENCODED_LEN(Length(Buf), 5));
    sodium_bin2base64(PAnsiChar(B64), Length(B64), @Buf[0], Length(Buf), sodium_base64_VARIANT_URLSAFE);
    WriteLn('sodium_bin2base64(5) => ', string(B64));
    SetLength(B64, _SODIUM_BASE64_ENCODED_LEN(Length(Buf), 7));
    sodium_bin2base64(PAnsiChar(B64), Length(B64), @Buf[0], Length(Buf), sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    WriteLn('sodium_bin2base64(7) => ', string(B64));

    var SeedBytes := randombytes_seedbytes;
    WriteLn('randombytes_seedbytes() => ', SeedBytes);

    randombytes_buf(@Buf[0], Length(Buf));
    SetLength(Hex, Length(Buf) * 2 + 1);
    sodium_bin2hex(PAnsiChar(Hex), Length(Hex), @Buf[0], Length(Buf));
    WriteLn('randombytes_buf() => ', string(Hex));
    WriteLn('randombytes_implementation_name() => ', string(UTF8String(randombytes_implementation_name)));

    WriteLn('sodium_runtime_has_neon() => ', sodium_runtime_has_neon);
    WriteLn('sodium_runtime_has_armcrypto() => ', sodium_runtime_has_armcrypto);
    WriteLn('sodium_runtime_has_sse2() => ', sodium_runtime_has_sse2);
    WriteLn('sodium_runtime_has_sse3() => ', sodium_runtime_has_sse3);
    WriteLn('sodium_runtime_has_ssse3() => ', sodium_runtime_has_ssse3);
    WriteLn('sodium_runtime_has_sse41() => ', sodium_runtime_has_sse41);
    WriteLn('sodium_runtime_has_avx() => ', sodium_runtime_has_avx);
    WriteLn('sodium_runtime_has_avx2() => ', sodium_runtime_has_avx2);
    WriteLn('sodium_runtime_has_avx512f() => ', sodium_runtime_has_avx512f);
    WriteLn('sodium_runtime_has_pclmul() => ', sodium_runtime_has_pclmul);
    WriteLn('sodium_runtime_has_aesni() => ', sodium_runtime_has_aesni);
    WriteLn('sodium_runtime_has_rdrand() => ', sodium_runtime_has_rdrand);

    crypto_aead_aegis128l_test;
    crypto_aead_aegis256_test;
    crypto_aead_aes256gcm_test;
    crypto_aead_chacha20poly1305_ietf_test;
    crypto_aead_chacha20poly1305_test;
    crypto_aead_xchacha20poly1305_ietf_test;

    sha256_test;
    sha512_test;
    crypto_hash_test;

    generic_hash_test;

    align_test;

    hmac_sha512_test;
    hmac_sha256_test;
    hmac_sha512256_test;

    crypto_sign_test;
    crypto_short_hash_test;
    crypto_auth_test;
    crypto_box_test;
    crypto_secretbox_test;
    crypto_secret_stream_test;
    crypto_kdf_test;
    crypto_kx_test;
    crypto_onetimeauth_test;
    crypto_scalarmult_test;
    crypto_pwhash_test;


    //sodium_misuse;

    ReadLn;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
