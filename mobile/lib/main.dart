// Mobile client. Two secrets, two jobs:
//   - login token  -> control plane (which terminals exist, who's online)
//   - pairing code  -> the E2E key that decrypts a terminal's bytes
// The relay is blind; frames are NaCl secretbox, byte-compatible with the
// desktop (Rust/dryoc).
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:pinenacl/x25519.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:web_socket_channel/web_socket_channel.dart';
import 'package:xterm/xterm.dart';

import 'api.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  final p = await SharedPreferences.getInstance();
  apiBase = p.getString('nt_server') ?? apiBase;
  runApp(const App());
}

class App extends StatelessWidget {
  const App({super.key});
  @override
  Widget build(BuildContext context) => MaterialApp(
        title: 'NewTerminal',
        theme: ThemeData.dark(useMaterial3: true),
        home: const Gate(),
      );
}

Uint8List? _decodeKey(String code) {
  try {
    final k = base64.decode(code.trim());
    return k.length == 32 ? k : null;
  } catch (_) {
    return null;
  }
}

/// Login -> pairing key -> terminal list.
class Gate extends StatefulWidget {
  const Gate({super.key});
  @override
  State<Gate> createState() => _GateState();
}

class _GateState extends State<Gate> {
  String? _token;
  Uint8List? _key;
  bool _loaded = false;

  @override
  void initState() {
    super.initState();
    SharedPreferences.getInstance().then((p) {
      final code = p.getString('pairing_code');
      setState(() {
        _token = p.getString('nt_token');
        _key = code == null ? null : _decodeKey(code);
        _loaded = true;
      });
    });
  }

  Future<void> _setToken(String? t) async {
    final p = await SharedPreferences.getInstance();
    if (t == null) {
      await p.remove('nt_token');
    } else {
      await p.setString('nt_token', t);
    }
    setState(() => _token = t);
  }

  @override
  Widget build(BuildContext context) {
    if (!_loaded) return const Scaffold(body: Center(child: CircularProgressIndicator()));
    if (_token == null) return LoginScreen(onToken: _setToken);
    if (_key == null) return PairingScreen(onPaired: (k) => setState(() => _key = k));
    return TerminalList(token: _token!, accountKey: _key!, onLogout: () => _setToken(null));
  }
}

class LoginScreen extends StatefulWidget {
  final void Function(String token) onToken;
  const LoginScreen({super.key, required this.onToken});
  @override
  State<LoginScreen> createState() => _LoginScreenState();
}

class _LoginScreenState extends State<LoginScreen> {
  final _email = TextEditingController();
  final _pw = TextEditingController();
  final _server = TextEditingController(text: apiBase);
  bool _register = false;
  bool _busy = false;
  String? _error;

  Future<void> _submit() async {
    setState(() {
      _busy = true;
      _error = null;
    });
    apiBase = _server.text.trim().replaceAll(RegExp(r'/$'), '');
    (await SharedPreferences.getInstance()).setString('nt_server', apiBase);
    try {
      final token = _register
          ? await Api.register(_email.text.trim(), _pw.text)
          : await Api.login(_email.text.trim(), _pw.text);
      widget.onToken(token);
    } catch (e) {
      setState(() => _error = '$e');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) => Scaffold(
        appBar: AppBar(title: Text(_register ? 'Create account' : 'Sign in')),
        body: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              TextField(controller: _server, decoration: const InputDecoration(labelText: 'server (https://…)')),
              const SizedBox(height: 12),
              TextField(controller: _email, decoration: const InputDecoration(labelText: 'email')),
              const SizedBox(height: 12),
              TextField(controller: _pw, obscureText: true, decoration: const InputDecoration(labelText: 'password')),
              if (_error != null) ...[
                const SizedBox(height: 12),
                Text(_error!, style: const TextStyle(color: Colors.redAccent)),
              ],
              const SizedBox(height: 20),
              FilledButton(onPressed: _busy ? null : _submit, child: Text(_register ? 'Register' : 'Sign in')),
              TextButton(
                onPressed: () => setState(() => _register = !_register),
                child: Text(_register ? 'Have an account? Sign in' : 'Need an account? Register'),
              ),
            ],
          ),
        ),
      );
}

class PairingScreen extends StatefulWidget {
  final void Function(Uint8List) onPaired;
  const PairingScreen({super.key, required this.onPaired});
  @override
  State<PairingScreen> createState() => _PairingScreenState();
}

class _PairingScreenState extends State<PairingScreen> {
  final _ctrl = TextEditingController();
  String? _error;

  Future<void> _submit() async {
    final k = _decodeKey(_ctrl.text);
    if (k == null) {
      setState(() => _error = 'Invalid pairing code (base64 of a 32-byte key)');
      return;
    }
    (await SharedPreferences.getInstance()).setString('pairing_code', _ctrl.text.trim());
    widget.onPaired(k);
  }

  @override
  Widget build(BuildContext context) => Scaffold(
        appBar: AppBar(title: const Text('Pair device')),
        body: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              const Text('Paste the pairing code shown on the desktop terminal.'),
              const SizedBox(height: 16),
              TextField(
                controller: _ctrl,
                maxLines: 2,
                decoration: InputDecoration(border: const OutlineInputBorder(), labelText: 'Pairing code', errorText: _error),
              ),
              const SizedBox(height: 16),
              FilledButton(onPressed: _submit, child: const Text('Save')),
            ],
          ),
        ),
      );
}

class TerminalList extends StatefulWidget {
  final String token;
  final Uint8List accountKey;
  final VoidCallback onLogout;
  const TerminalList({super.key, required this.token, required this.accountKey, required this.onLogout});
  @override
  State<TerminalList> createState() => _TerminalListState();
}

class _TerminalListState extends State<TerminalList> {
  List<TerminalInfo> _terms = [];
  String? _error;
  WebSocketChannel? _control;
  bool _disposed = false;
  int _backoff = 1;

  @override
  void initState() {
    super.initState();
    _refresh();
    _openControl();
  }

  Future<void> _refresh() async {
    try {
      final t = await Api.terminals(widget.token);
      if (mounted) setState(() { _terms = t; _error = null; });
    } catch (e) {
      if (mounted) setState(() => _error = '$e');
    }
  }

  // Control WS: live presence pushes update the online dots without polling.
  // Reconnects with backoff; a fresh list on (re)connect repairs dots missed
  // while disconnected.
  void _openControl() {
    if (_disposed) return;
    final ch = WebSocketChannel.connect(Uri.parse(wsUrl));
    _control = ch;
    ch.sink.add(jsonEncode({'type': 'hello', 'token': widget.token, 'role': 'control'}));
    _refresh();
    ch.stream.listen((msg) {
      _backoff = 1;
      if (msg is! String) return;
      final m = jsonDecode(msg) as Map<String, dynamic>;
      if (m['type'] != 'presence') return;
      setState(() {
        _terms = _terms
            .map((t) => t.id == m['terminal'] ? TerminalInfo(t.id, t.name, m['online'] as bool) : t)
            .toList();
      });
    }, onError: (_) => _reconnect(), onDone: _reconnect);
  }

  void _reconnect() {
    if (_disposed) return;
    Future.delayed(Duration(seconds: _backoff), _openControl);
    _backoff = (_backoff * 2).clamp(1, 30);
  }

  @override
  void dispose() {
    _disposed = true;
    _control?.sink.close();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => Scaffold(
        appBar: AppBar(
          title: const Text('Terminals'),
          actions: [
            IconButton(icon: const Icon(Icons.refresh), onPressed: _refresh),
            IconButton(icon: const Icon(Icons.logout), onPressed: widget.onLogout),
          ],
        ),
        body: RefreshIndicator(
          onRefresh: _refresh,
          child: _terms.isEmpty
              ? ListView(children: [
                  Padding(
                    padding: const EdgeInsets.all(24),
                    child: Text(_error ?? 'No terminals yet. Open the desktop app to register one.'),
                  )
                ])
              : ListView(
                  children: _terms
                      .map((t) => ListTile(
                            leading: Icon(Icons.circle, size: 12, color: t.online ? Colors.green : Colors.grey),
                            title: Text(t.name),
                            subtitle: Text(t.id.substring(0, 8)),
                            enabled: t.online,
                            onTap: () => Navigator.push(
                              context,
                              MaterialPageRoute(
                                builder: (_) => TerminalScreen(token: widget.token, terminal: t.id, accountKey: widget.accountKey, name: t.name),
                              ),
                            ),
                          ))
                      .toList(),
                ),
        ),
      );
}

class TerminalScreen extends StatefulWidget {
  final String token;
  final String terminal;
  final String name;
  final Uint8List accountKey;
  const TerminalScreen({super.key, required this.token, required this.terminal, required this.name, required this.accountKey});
  @override
  State<TerminalScreen> createState() => _TerminalScreenState();
}

class _TerminalScreenState extends State<TerminalScreen> {
  late final SecretBox _box = SecretBox(widget.accountKey);
  late final Terminal _terminal = Terminal(maxLines: 10000);
  WebSocketChannel? _channel;
  bool _disposed = false;
  int _backoff = 1;

  @override
  void initState() {
    super.initState();
    _connect();
    _terminal.onOutput = (data) => _send(utf8.encode(data));
  }

  // Reconnects with backoff; the server replays recent scrollback on rejoin.
  void _connect() {
    if (_disposed) return;
    final ch = WebSocketChannel.connect(Uri.parse(wsUrl));
    _channel = ch;
    ch.sink.add(jsonEncode({'type': 'hello', 'token': widget.token, 'terminal': widget.terminal, 'role': 'viewer'}));
    ch.stream.listen((msg) {
      _backoff = 1;
      if (msg is String) return;
      try {
        final clear = _box.decrypt(EncryptedMessage.fromList(Uint8List.fromList(msg as List<int>)));
        _terminal.write(utf8.decode(clear, allowMalformed: true));
      } catch (_) {}
    }, onError: (_) => _reconnect(), onDone: _reconnect);
  }

  void _reconnect() {
    if (_disposed) return;
    Future.delayed(Duration(seconds: _backoff), _connect);
    _backoff = (_backoff * 2).clamp(1, 30);
  }

  // Encrypt and send keystrokes/shortcuts to the relay.
  void _send(List<int> bytes) {
    final frame = _box.encrypt(Uint8List.fromList(bytes));
    _channel?.sink.add(Uint8List.fromList(frame));
  }

  @override
  void dispose() {
    _disposed = true;
    _channel?.sink.close();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => Scaffold(
        appBar: AppBar(title: Text(widget.name)),
        body: Column(
          children: [
            Expanded(child: TerminalView(_terminal)),
            _ShortcutBar(onKey: _send),
          ],
        ),
      );
}

// Quick-key bar above the keyboard — the shortcuts req3 asked for.
class _ShortcutBar extends StatelessWidget {
  final void Function(List<int>) onKey;
  const _ShortcutBar({required this.onKey});

  static const _keys = <(String, List<int>)>[
    ('Esc', [0x1b]),
    ('Tab', [0x09]),
    ('^C', [0x03]),
    ('^D', [0x04]),
    ('^Z', [0x1a]),
    ('←', [0x1b, 0x5b, 0x44]),
    ('↓', [0x1b, 0x5b, 0x42]),
    ('↑', [0x1b, 0x5b, 0x41]),
    ('→', [0x1b, 0x5b, 0x43]),
    ('⏎', [0x0d]),
  ];

  @override
  Widget build(BuildContext context) => SafeArea(
        top: false,
        child: SizedBox(
          height: 44,
          child: ListView(
            scrollDirection: Axis.horizontal,
            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 6),
            children: _keys
                .map((k) => Padding(
                      padding: const EdgeInsets.symmetric(horizontal: 3),
                      child: OutlinedButton(
                        style: OutlinedButton.styleFrom(padding: const EdgeInsets.symmetric(horizontal: 12), minimumSize: const Size(0, 32)),
                        onPressed: () => onKey(k.$2),
                        child: Text(k.$1),
                      ),
                    ))
                .toList(),
          ),
        ),
      );
}
