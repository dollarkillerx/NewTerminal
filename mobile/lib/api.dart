// Control-plane HTTP client.
import 'dart:convert';
import 'package:http/http.dart' as http;

// Server base is user-configurable (point at your Cloudflare domain, e.g.
// https://term.example.com) and loaded from prefs at startup; ws is derived.
String apiBase = 'http://127.0.0.1:8799';
String get wsUrl => '${apiBase.replaceFirst(RegExp(r'^http'), 'ws')}/ws';

class TerminalInfo {
  final String id;
  final String name;
  final bool online;
  TerminalInfo(this.id, this.name, this.online);
  factory TerminalInfo.fromJson(Map<String, dynamic> j) =>
      TerminalInfo(j['id'] as String, j['name'] as String, (j['online'] as bool?) ?? false);
}

class Api {
  static Future<String> _auth(String path, String email, String password) async {
    final r = await http.post(
      Uri.parse('$apiBase/$path'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'email': email, 'password': password}),
    );
    final body = jsonDecode(r.body) as Map<String, dynamic>;
    if (r.statusCode != 200) throw Exception(body['error'] ?? 'error ${r.statusCode}');
    return body['token'] as String;
  }

  static Future<String> login(String email, String password) => _auth('login', email, password);
  static Future<String> register(String email, String password) => _auth('register', email, password);

  static Future<List<TerminalInfo>> terminals(String token) async {
    final r = await http.get(Uri.parse('$apiBase/terminals'),
        headers: {'Authorization': 'Bearer $token'});
    if (r.statusCode != 200) throw Exception('list failed (${r.statusCode})');
    final list = jsonDecode(r.body) as List<dynamic>? ?? [];
    return list.map((e) => TerminalInfo.fromJson(e as Map<String, dynamic>)).toList();
  }
}
