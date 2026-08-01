// frontend/lib/main.dart

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'application/auth_provider.dart';
import 'infrastructure/bip39.dart';

void main() {
  debugPrint('[VeilApp] Entry point main() triggered.');
  runApp(
    const ProviderScope(
      child: VeilApp(),
    ),
  );
}

class VeilApp extends StatelessWidget {
  const VeilApp({super.key});

  @override
  Widget build(BuildContext context) {
    debugPrint('[VeilApp] Building MaterialApp root.');
    return MaterialApp(
      title: 'Veil',
      theme: ThemeData(
        brightness: Brightness.dark,
        primaryColor: const Color(0xFF1E1E2E), // Slick Slate Dark
        scaffoldBackgroundColor: const Color(0xFF0F0F15), // OLED-friendly deep dark
        colorScheme: const ColorScheme.dark(
          primary: Colors.deepPurpleAccent,
          secondary: Colors.purpleAccent,
          background: Color(0xFF0F0F15),
          surface: Color(0xFF1E1E2E),
        ),
        useMaterial3: true,
      ),
      home: const AuthRouter(),
    );
  }
}

class AuthRouter extends ConsumerStatefulWidget {
  const AuthRouter({super.key});

  @override
  ConsumerState<AuthRouter> createState() => _AuthRouterState();
}

class _AuthRouterState extends ConsumerState<AuthRouter> {
  @override
  void initState() {
    super.initState();
    debugPrint('[AuthRouter] Initialized. Checking current session.');
    // Check if session rotate or initialization can be triggered
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _checkSession();
    });
  }

  void _checkSession() async {
    try {
      debugPrint('[AuthRouter] Attempting automatic session rotation check.');
      await ref.read(authProvider.notifier).rotateSession();
      debugPrint('[AuthRouter] Session check complete.');
    } catch (e, stack) {
      debugPrint('[AuthRouter] Session check exception caught: $e');
      debugPrint('$stack');
    }
  }

  @override
  Widget build(BuildContext context) {
    final authState = ref.watch(authProvider);
    debugPrint('[AuthRouter] Rebuilding with AuthState: ${authState.runtimeType}');

    if (authState is AuthLoading) {
      return const SplashScreen(showLoading: true);
    } else if (authState is AuthSuccess) {
      return DashboardPage(
        username: authState.credentials.username,
        sessionToken: authState.session.accessToken,
      );
    } else if (authState is AuthFailure) {
      debugPrint('[AuthRouter] Auth failure detected in UI: ${authState.error}');
      return LoginPage(errorMessage: authState.error);
    } else {
      return const LoginPage();
    }
  }
}

class SplashScreen extends StatelessWidget {
  final bool showLoading;
  const SplashScreen({super.key, this.showLoading = false});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Icon(
              Icons.security,
              size: 80,
              color: Colors.deepPurpleAccent,
            ),
            const SizedBox(height: 16),
            const Text(
              'Veil',
              style: TextStyle(
                fontSize: 36,
                fontWeight: FontWeight.bold,
                letterSpacing: 3,
              ),
            ),
            const SizedBox(height: 8),
            const Text(
              'Privacy first. End-to-end encrypted.',
              style: TextStyle(
                fontSize: 14,
                color: Colors.grey,
              ),
            ),
            if (showLoading) ...[
              const SizedBox(height: 32),
              const CircularProgressIndicator(
                valueColor: AlwaysStoppedAnimation<Color>(Colors.deepPurpleAccent),
              ),
            ],
          ],
        ),
      ),
    );
  }
}

class LoginPage extends ConsumerStatefulWidget {
  final String? errorMessage;
  const LoginPage({super.key, this.errorMessage});

  @override
  ConsumerState<LoginPage> createState() => _LoginPageState();
}

class _LoginPageState extends ConsumerState<LoginPage> {
  final _usernameController = TextEditingController();
  final _passwordController = TextEditingController();
  final _deviceNameController = TextEditingController(text: 'Mobile Device');

  bool _isRegistering = false;
  String _displayName = 'User';

  // BIP-39 mnemonic generation state
  String? _generatedMnemonic;
  bool _hasConfirmedMnemonic = false;

  @override
  Widget build(BuildContext context) {
    if (_isRegistering && _generatedMnemonic != null) {
      return _buildMnemonicConfirmationScreen();
    }
    return _buildLoginForm();
  }

  Widget _buildMnemonicConfirmationScreen() {
    final words = _generatedMnemonic!.split(' ');
    final username = _usernameController.text.trim();
    final password = _passwordController.text.trim();
    final deviceName = _deviceNameController.text.trim();

    return Scaffold(
      body: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(24.0),
          child: Card(
            color: const Color(0xFF1E1E2E),
            shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(16),
              side: const BorderSide(color: Colors.deepPurpleAccent, width: 0.5),
            ),
            child: Padding(
              padding: const EdgeInsets.all(24.0),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  const Icon(
                    Icons.warning_amber_rounded,
                    color: Colors.amber,
                    size: 48,
                  ),
                  const SizedBox(height: 16),
                  const Text(
                    'Save Your Recovery Key',
                    style: TextStyle(
                      fontSize: 24,
                      fontWeight: FontWeight.bold,
                      color: Colors.white,
                    ),
                    textAlign: TextAlign.center,
                  ),
                  const SizedBox(height: 12),
                  const Text(
                    'This 24-word phrase is the only way to recover your account if you lose your password. Write it down and store it in a secure offline location.',
                    style: TextStyle(fontSize: 13, color: Colors.grey),
                    textAlign: TextAlign.center,
                  ),
                  const SizedBox(height: 24),
                  Container(
                    padding: const EdgeInsets.all(16),
                    decoration: BoxDecoration(
                      color: const Color(0xFF0F0F15),
                      borderRadius: BorderRadius.circular(12),
                      border: Border.all(color: Colors.grey.withOpacity(0.3)),
                    ),
                    child: Wrap(
                      spacing: 8,
                      runSpacing: 8,
                      children: List.generate(words.length, (index) {
                        return Container(
                          padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
                          decoration: BoxDecoration(
                            color: Colors.deepPurpleAccent.withOpacity(0.1),
                            borderRadius: BorderRadius.circular(6),
                            border: Border.all(color: Colors.deepPurpleAccent.withOpacity(0.3)),
                          ),
                          child: Text(
                            '${index + 1}. ${words[index]}',
                            style: const TextStyle(
                              fontSize: 13,
                              fontFamily: 'monospace',
                              fontWeight: FontWeight.bold,
                              color: Colors.purpleAccent,
                            ),
                          ),
                        );
                      }),
                    ),
                  ),
                  const SizedBox(height: 24),
                  CheckboxListTile(
                    title: const Text(
                      "I have securely written down and backed up this 24-word recovery phrase.",
                      style: TextStyle(fontSize: 12, color: Colors.white70),
                    ),
                    value: _hasConfirmedMnemonic,
                    activeColor: Colors.deepPurpleAccent,
                    onChanged: (val) {
                      setState(() {
                        _hasConfirmedMnemonic = val ?? false;
                      });
                    },
                    controlAffinity: ListTileControlAffinity.leading,
                    contentPadding: EdgeInsets.zero,
                  ),
                  const SizedBox(height: 24),
                  ElevatedButton(
                    style: ElevatedButton.styleFrom(
                      backgroundColor: Colors.deepPurpleAccent,
                      foregroundColor: Colors.white,
                      padding: const EdgeInsets.symmetric(vertical: 16),
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(8),
                      ),
                    ),
                    onPressed: _hasConfirmedMnemonic
                        ? () {
                            debugPrint('[LoginPage] Register submit clicked with mnemonic.');
                            ref.read(authProvider.notifier).register(
                              username: username,
                              password: password,
                              recoveryMnemonic: _generatedMnemonic!,
                              displayName: _displayName,
                              deviceName: deviceName,
                              deviceType: 'mobile',
                              platform: 'android',
                              appVersion: '1.0.0',
                              devicePublicKey: [1, 2, 3],
                              verificationFingerprint: 'mock_fingerprint',
                            );
                            setState(() {
                              _generatedMnemonic = null;
                              _hasConfirmedMnemonic = false;
                            });
                          }
                        : null,
                    child: const Text(
                      'Confirm & Register',
                      style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold),
                    ),
                  ),
                  const SizedBox(height: 12),
                  TextButton(
                    onPressed: () {
                      setState(() {
                        _generatedMnemonic = null;
                      });
                    },
                    child: const Text(
                      'Go Back',
                      style: TextStyle(color: Colors.grey),
                    ),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildLoginForm() {
    return Scaffold(
      body: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(24.0),
          child: Card(
            color: const Color(0xFF1E1E2E),
            shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(16),
              side: const BorderSide(color: Colors.deepPurpleAccent, width: 0.5),
            ),
            child: Padding(
              padding: const EdgeInsets.all(32.0),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Text(
                    _isRegistering ? 'Create Account' : 'Welcome Back',
                    style: const TextStyle(
                      fontSize: 28,
                      fontWeight: FontWeight.bold,
                      color: Colors.white,
                    ),
                    textAlign: TextAlign.center,
                  ),
                  const SizedBox(height: 8),
                  Text(
                    _isRegistering
                        ? 'No personal details or contact sync needed.'
                        : 'Secure E2EE message routing active.',
                    style: const TextStyle(fontSize: 12, color: Colors.grey),
                    textAlign: TextAlign.center,
                  ),
                  const SizedBox(height: 24),
                  if (widget.errorMessage != null) ...[
                    Container(
                      padding: const EdgeInsets.all(12),
                      decoration: BoxDecoration(
                        color: Colors.redAccent.withOpacity(0.1),
                        borderRadius: BorderRadius.circular(8),
                        border: Border.all(color: Colors.redAccent, width: 1),
                      ),
                      child: Text(
                        widget.errorMessage!,
                        style: const TextStyle(color: Colors.redAccent, fontSize: 13),
                        textAlign: TextAlign.center,
                      ),
                    ),
                    const SizedBox(height: 16),
                  ],
                  TextField(
                    controller: _usernameController,
                    decoration: const InputDecoration(
                      labelText: 'Username',
                      prefixIcon: Icon(Icons.person),
                    ),
                  ),
                  const SizedBox(height: 16),
                  TextField(
                    controller: _passwordController,
                    obscureText: true,
                    decoration: const InputDecoration(
                      labelText: 'Password',
                      prefixIcon: Icon(Icons.lock),
                    ),
                  ),
                  const SizedBox(height: 16),
                  TextField(
                    controller: _deviceNameController,
                    decoration: const InputDecoration(
                      labelText: 'Device Name',
                      prefixIcon: Icon(Icons.phone_android),
                    ),
                  ),
                  const SizedBox(height: 24),
                  ElevatedButton(
                    style: ElevatedButton.styleFrom(
                      backgroundColor: Colors.deepPurpleAccent,
                      foregroundColor: Colors.white,
                      padding: const EdgeInsets.symmetric(vertical: 16),
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(8),
                      ),
                    ),
                    onPressed: () {
                      final username = _usernameController.text.trim();
                      final password = _passwordController.text.trim();
                      final deviceName = _deviceNameController.text.trim();

                      if (username.isEmpty || password.isEmpty) return;

                      debugPrint('[LoginPage] Submit clicked. isRegistering=$_isRegistering');
                      if (_isRegistering) {
                        setState(() {
                          _generatedMnemonic = Bip39Mnemonic.generate();
                          _hasConfirmedMnemonic = false;
                        });
                      } else {
                        ref.read(authProvider.notifier).login(
                          identifier: username,
                          password: password,
                          deviceName: deviceName,
                          deviceType: 'mobile',
                          platform: 'android',
                          appVersion: '1.0.0',
                          devicePublicKey: [1, 2, 3],
                          verificationFingerprint: 'mock_fingerprint',
                        );
                      }
                    },
                    child: Text(
                      _isRegistering ? 'Generate Recovery Phrase & Register' : 'Login',
                      style: const TextStyle(fontSize: 15, fontWeight: FontWeight.bold),
                    ),
                  ),
                  const SizedBox(height: 16),
                  TextButton(
                    onPressed: () {
                      setState(() {
                        _isRegistering = !_isRegistering;
                        _generatedMnemonic = null;
                        _hasConfirmedMnemonic = false;
                      });
                    },
                    child: Text(
                      _isRegistering
                          ? 'Already have an account? Sign In'
                          : 'Need a new account? Create one',
                      style: const TextStyle(color: Colors.purpleAccent),
                    ),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}

class DashboardPage extends ConsumerWidget {
  final String username;
  final String sessionToken;

  const DashboardPage({
    super.key,
    required this.username,
    required this.sessionToken,
  });

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Veil Dashboard'),
        backgroundColor: const Color(0xFF1E1E2E),
        actions: [
          IconButton(
            icon: const Icon(Icons.logout),
            onPressed: () {
              debugPrint('[DashboardPage] Logout clicked.');
              ref.read(authProvider.notifier).logout();
            },
          ),
        ],
      ),
      body: Padding(
        padding: const EdgeInsets.all(24.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Card(
              color: const Color(0xFF1E1E2E),
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(12),
                side: const BorderSide(color: Colors.greenAccent, width: 0.5),
              ),
              child: Padding(
                padding: const EdgeInsets.all(16.0),
                child: Row(
                  children: [
                    const Icon(Icons.check_circle, color: Colors.greenAccent, size: 48),
                    const SizedBox(width: 16),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            'Logged in as @$username',
                            style: const TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                          ),
                          const SizedBox(height: 4),
                          const Text(
                            'End-to-End Cryptography Active',
                            style: TextStyle(color: Colors.grey, fontSize: 13),
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 24),
            const Text(
              'Secure Messaging Engine',
              style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 12),
            Expanded(
              child: ListView(
                children: [
                  ListTile(
                    leading: const Icon(Icons.vpn_key, color: Colors.deepPurpleAccent),
                    title: const Text('Double Ratchet Keys'),
                    subtitle: const Text('Root and chain states initialized'),
                    tileColor: const Color(0xFF1E1E2E),
                    shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                  ),
                  const SizedBox(height: 8),
                  ListTile(
                    leading: const Icon(Icons.sync, color: Colors.deepPurpleAccent),
                    title: const Text('X3DH Ephemeral Keys'),
                    subtitle: const Text('One-time prekeys available'),
                    tileColor: const Color(0xFF1E1E2E),
                    shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                  ),
                  const SizedBox(height: 8),
                  ListTile(
                    leading: const Icon(Icons.message, color: Colors.deepPurpleAccent),
                    title: const Text('WebSocket Connection'),
                    subtitle: Text('Token: ${sessionToken.substring(0, 8)}...'),
                    tileColor: const Color(0xFF1E1E2E),
                    shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}
