program test_kx;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
  libsodium in '..\lib\libsodium.pas',
  Sodium.Utils in '..\lib\Sodium.Utils.pas',
  Sodium.Kx in '..\lib\Sodium.Kx.pas';

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

  WriteLn('client_pk=', THexEncode.FromBytes(@client_pk[0], SizeOf(client_pk)));
  WriteLn('client_sk=', THexEncode.FromBytes(@client_sk[0], SizeOf(client_sk)));
  WriteLn('client_rx=', THexEncode.FromBytes(@client_rx[0], SizeOf(client_rx)));
  WriteLn('client_tx=', THexEncode.FromBytes(@client_tx[0], SizeOf(client_tx)));

  WriteLn('server_pk=', THexEncode.FromBytes(@server_pk[0], SizeOf(server_pk)));
  WriteLn('server_sk=', THexEncode.FromBytes(@server_sk[0], SizeOf(server_sk)));
  WriteLn('server_rx=', THexEncode.FromBytes(@server_rx[0], SizeOf(server_rx)));
  WriteLn('server_tx=', THexEncode.FromBytes(@server_tx[0], SizeOf(server_tx)));
end;

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

      WriteLn('ClientPk=', THexEncode.FromBytes(@ClientPk[0], SizeOf(ClientPk)));
      WriteLn('ClientSk=', THexEncode.FromBytes(@ClientSk[0], SizeOf(ClientSk)));
      WriteLn('ClientRx=', THexEncode.FromBytes(@ClientRx[0], SizeOf(ClientRx)));
      WriteLn('ClientTx=', THexEncode.FromBytes(@ClientTx[0], SizeOf(ClientTx)));

      WriteLn('ServerPk=', THexEncode.FromBytes(@ServerPk[0], SizeOf(ServerPk)));
      WriteLn('ServerSk=', THexEncode.FromBytes(@ServerSk[0], SizeOf(ServerSk)));
      WriteLn('ServerRx=', THexEncode.FromBytes(@ServerRx[0], SizeOf(ServerRx)));
      WriteLn('ServerTx=', THexEncode.FromBytes(@ServerTx[0], SizeOf(ServerTx)));
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
    Write('API...'); test_api(client_pk, client_sk, server_pk, server_sk);
    Write('Wrapper...'); test(client_pk, client_sk, server_pk, server_sk);

    ReadLn;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
