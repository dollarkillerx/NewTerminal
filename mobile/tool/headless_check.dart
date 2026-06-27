// Headless check of the mobile control + data plane against the live server:
//   register -> create terminal -> presence online -> viewer decrypts host output.
// Uses the app's real api.dart + pinenacl crypto. Run from mobile/:
//   dart run tool/headless_check.dart
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:http/http.dart' as http;
import 'package:pinenacl/x25519.dart';
import 'package:web_socket_channel/web_socket_channel.dart';

import 'package:mobile/api.dart';

var failed = 0;
void check(bool ok, String msg) {
  stdout.writeln('${ok ? "PASS" : "FAIL"} $msg');
  if (!ok) failed++;
}

Future<void> main() async {
  final email = 'u${DateTime.now().microsecondsSinceEpoch}@x.com';

  // 1. register -> token (api.dart)
  final token = await Api.register(email, 'pw123456');
  check(token.isNotEmpty, 'register returns token');

  // 2. create a terminal (what the desktop does)
  final tr = await http.post(Uri.parse('$apiBase/terminals'),
      headers: {'Authorization': 'Bearer $token', 'Content-Type': 'application/json'},
      body: jsonEncode({'name': 'test-mac'}));
  final termId = (jsonDecode(tr.body) as Map<String, dynamic>)['id'] as String;
  check(termId.isNotEmpty, 'terminal registered');

  // 3. list shows it, offline (api.dart)
  var list = await Api.terminals(token);
  check(list.length == 1 && !list.first.online, 'list shows terminal offline');

  // shared E2E key (the pairing code, here just generated for both ends)
  final key = Uint8List.fromList(List.generate(32, (_) => Random.secure().nextInt(256)));
  final box = SecretBox(key);

  // 4. control WS receives presence; host comes online
  final control = WebSocketChannel.connect(Uri.parse(wsUrl));
  final presence = <Map<String, dynamic>>[];
  control.sink.add(jsonEncode({'type': 'hello', 'token': token, 'role': 'control'}));
  control.stream.listen((m) { if (m is String) presence.add(jsonDecode(m) as Map<String, dynamic>); });
  await Future<void>.delayed(const Duration(milliseconds: 150));

  final hostWs = WebSocketChannel.connect(Uri.parse(wsUrl));
  hostWs.sink.add(jsonEncode({'type': 'hello', 'token': token, 'terminal': termId, 'role': 'host'}));
  await Future<void>.delayed(const Duration(milliseconds: 200));
  check(presence.any((p) => p['terminal'] == termId && p['online'] == true), 'control got presence online');

  list = await Api.terminals(token);
  check(list.first.online, 'list reflects online');

  // 5. viewer decrypts host output (the data plane)
  final viewerWs = WebSocketChannel.connect(Uri.parse(wsUrl));
  var clear = '';
  viewerWs.stream.listen((m) {
    if (m is String) return;
    try {
      clear += utf8.decode(box.decrypt(EncryptedMessage.fromList(Uint8List.fromList(m as List<int>))), allowMalformed: true);
    } catch (_) {}
  });
  viewerWs.sink.add(jsonEncode({'type': 'hello', 'token': token, 'terminal': termId, 'role': 'viewer'}));
  await Future<void>.delayed(const Duration(milliseconds: 150));

  final frame = box.encrypt(Uint8List.fromList(utf8.encode('HELLO_FROM_HOST')));
  hostWs.sink.add(Uint8List.fromList(frame));
  await Future<void>.delayed(const Duration(milliseconds: 300));
  check(clear.contains('HELLO_FROM_HOST'), 'viewer decrypted host output');

  await control.sink.close();
  await hostWs.sink.close();
  await viewerWs.sink.close();
  stdout.writeln(failed == 0 ? '\nALL PASS' : '\n$failed FAILED');
  exit(failed == 0 ? 0 : 1);
}
