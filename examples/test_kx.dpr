program test_kx;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
{$if defined(API)}
  libsodium,
{$endif}
  Sodium.Kx,
  Sodium.Utils;

{$if defined(API)}
procedure test_api(client_pk: TCryptoKxPublicKey; client_sk: TCryptoKxSecretKey;
  server_pk: TCryptoKxPublicKey; server_sk: TCryptoKxSecretKey);
var
  client_rx: TCryptoKxSessionKey;
  client_tx: TCryptoKxSessionKey;

  server_rx: TCryptoKxSessionKey;
  server_tx: TCryptoKxSessionKey;
begin
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

  WriteLn('client_pk=', TBytes.ToHex(client_pk, SizeOf(client_pk)));
  WriteLn('client_sk=', TBytes.ToHex(client_sk, SizeOf(client_sk)));
  WriteLn('client_rx=', TBytes.ToHex(client_rx, SizeOf(client_rx)));
  WriteLn('client_tx=', TBytes.ToHex(client_tx, SizeOf(client_tx)));

  WriteLn('server_pk=', TBytes.ToHex(server_pk, SizeOf(server_pk)));
  WriteLn('server_sk=', TBytes.ToHex(server_sk, SizeOf(server_sk)));
  WriteLn('server_rx=', TBytes.ToHex(server_rx, SizeOf(server_rx)));
  WriteLn('server_tx=', TBytes.ToHex(server_tx, SizeOf(server_tx)));
end;
{$endif}

procedure test(ClientPk: TCryptoKxPublicKey; ClientSk: TCryptoKxSecretKey;
  ServerPk: TCryptoKxPublicKey; ServerSk: TCryptoKxSecretKey);
var
  ClientRx: TCryptoKxSessionKey;
  ClientTx: TCryptoKxSessionKey;

  ServerRx: TCryptoKxSessionKey;
  ServerTx: TCryptoKxSessionKey;
begin
  if TCryptoKx.ClientSessionKeys(ClientRx, ClientTx, ClientPk, ClientSk, ServerPk) then
    if TCryptoKx.ServerSessionKeys(ServerRx, ServerTx, ServerPk, ServerSk, ClientPk) then
    begin
      WriteLn('SUCCESS');

      WriteLn('ClientPk=', TBytes.ToHex(ClientPk, SizeOf(ClientPk)));
      WriteLn('ClientSk=', TBytes.ToHex(ClientSk, SizeOf(ClientSk)));
      WriteLn('ClientRx=', TBytes.ToHex(ClientRx, SizeOf(ClientRx)));
      WriteLn('ClientTx=', TBytes.ToHex(ClientTx, SizeOf(ClientTx)));

      WriteLn('ServerPk=', TBytes.ToHex(ServerPk, SizeOf(ServerPk)));
      WriteLn('ServerSk=', TBytes.ToHex(ServerSk, SizeOf(ServerSk)));
      WriteLn('ServerRx=', TBytes.ToHex(ServerRx, SizeOf(ServerRx)));
      WriteLn('ServerTx=', TBytes.ToHex(ServerTx, SizeOf(ServerTx)));
    end
    else
      WriteLn('FAILED (SERVER SESSION KEYS)')
  else
    WriteLn('FAILED (CLIENT SESSION KEYS)');
end;

var
  client_pk: TCryptoKxPublicKey;
  client_sk: TCryptoKxSecretKey;
  server_pk: TCryptoKxPublicKey;
  server_sk: TCryptoKxSecretKey;

begin
  try
    TCryptoKx.Keypair(client_pk, client_sk);
    TCryptoKx.Keypair(server_pk, server_sk);

    WriteLn('TCryptoKx.Primitive=', TCryptoKx.Primitive);
  {$if defined(API)}
    Write('API...'); test_api(client_pk, client_sk, server_pk, server_sk);
  {$endif}
    Write('Wrapper...'); test(client_pk, client_sk, server_pk, server_sk);

    ReadLn;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
