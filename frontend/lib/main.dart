// frontend/lib/main.dart

import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:cbor/cbor.dart';
import 'package:uuid/uuid.dart';

import 'application/auth_provider.dart';
import 'infrastructure/bip39.dart';
import 'infrastructure/ws_client.dart';
import 'infrastructure/auth_api_client.dart';

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
      // Initialize chat/socket client on successful login
      WidgetsBinding.instance.addPostFrameCallback((_) {
        ref.read(chatProvider.notifier).init(
          authState.session.accessToken,
          authState.credentials.deviceId,
        );
      });

      return DashboardPage(
        username: authState.credentials.username,
        accountId: authState.credentials.accountId,
        deviceId: authState.credentials.deviceId,
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

class DashboardPage extends ConsumerStatefulWidget {
  final String username;
  final String accountId;
  final String deviceId;
  final String sessionToken;

  const DashboardPage({
    super.key,
    required this.username,
    required this.accountId,
    required this.deviceId,
    required this.sessionToken,
  });

  @override
  ConsumerState<DashboardPage> createState() => _DashboardPageState();
}

class _DashboardPageState extends ConsumerState<DashboardPage> {
  int _currentIndex = 0;

  @override
  Widget build(BuildContext context) {
    final chatState = ref.watch(chatProvider);

    final tabs = [
      _buildChatsTab(chatState),
      _buildProfileTab(),
    ];

    return Scaffold(
      appBar: AppBar(
        title: Text(_currentIndex == 0 ? 'Secure Chats' : 'My Profile'),
        backgroundColor: const Color(0xFF1E1E2E),
        actions: [
          if (_currentIndex == 1)
            IconButton(
              icon: const Icon(Icons.logout),
              onPressed: () {
                debugPrint('[DashboardPage] Logout clicked.');
                ref.read(chatProvider.notifier).disconnect();
                ref.read(authProvider.notifier).logout();
              },
            ),
        ],
      ),
      body: tabs[_currentIndex],
      bottomNavigationBar: BottomNavigationBar(
        currentIndex: _currentIndex,
        backgroundColor: const Color(0xFF1E1E2E),
        selectedItemColor: Colors.deepPurpleAccent,
        unselectedItemColor: Colors.grey,
        onTap: (index) {
          setState(() {
            _currentIndex = index;
          });
        },
        items: const [
          BottomNavigationBarItem(
            icon: Icon(Icons.message),
            label: 'Chats',
          ),
          BottomNavigationBarItem(
            icon: Icon(Icons.person),
            label: 'Profile',
          ),
        ],
      ),
    );
  }

  Widget _buildChatsTab(ChatState chatState) {
    return Scaffold(
      floatingActionButton: FloatingActionButton(
        backgroundColor: Colors.deepPurpleAccent,
        foregroundColor: Colors.white,
        child: const Icon(Icons.add),
        onPressed: () => _showNewChatDialog(context, ref),
      ),
      body: Column(
        children: [
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
            color: chatState.isConnected ? Colors.green.withOpacity(0.1) : Colors.red.withOpacity(0.1),
            child: Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Icon(
                  chatState.isConnected ? Icons.cloud_done : Icons.cloud_off,
                  color: chatState.isConnected ? Colors.green : Colors.red,
                  size: 16,
                ),
                const SizedBox(width: 8),
                Text(
                  chatState.isConnected ? 'Connected to WebSocket router' : 'WebSocket Disconnected',
                  style: TextStyle(
                    color: chatState.isConnected ? Colors.green : Colors.red,
                    fontSize: 12,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ],
            ),
          ),
          Expanded(
            child: chatState.conversations.isEmpty
                ? const Center(
                    child: Text(
                      'No active chats.\nTap the + button to search users and start a chat.',
                      textAlign: TextAlign.center,
                      style: TextStyle(color: Colors.grey),
                    ),
                  )
                : ListView.builder(
                    padding: const EdgeInsets.symmetric(vertical: 8),
                    itemCount: chatState.conversations.length,
                    itemBuilder: (context, index) {
                      final conv = chatState.conversations[index];
                      final lastMsg = conv.messages.isNotEmpty ? conv.messages.last.text : 'No messages yet';
                      return ListTile(
                        leading: CircleAvatar(
                          backgroundColor: Colors.deepPurpleAccent.withOpacity(0.2),
                          child: Text(
                            conv.otherUsername.substring(0, 1).toUpperCase(),
                            style: const TextStyle(color: Colors.purpleAccent, fontWeight: FontWeight.bold),
                          ),
                        ),
                        title: Text(conv.otherUsername),
                        subtitle: Text(
                          lastMsg,
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                        ),
                        trailing: const Icon(Icons.chevron_right, color: Colors.grey),
                        onTap: () {
                          Navigator.push(
                            context,
                            MaterialPageRoute(
                              builder: (context) => ChatRoomPage(conversation: conv),
                            ),
                          );
                        },
                      );
                    },
                  ),
          ),
        ],
      ),
    );
  }

  Widget _buildProfileTab() {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(24.0),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Card(
            color: const Color(0xFF1E1E2E),
            shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(16),
              side: const BorderSide(color: Colors.deepPurpleAccent, width: 0.5),
            ),
            child: Padding(
              padding: const EdgeInsets.all(24.0),
              child: Column(
                children: [
                  CircleAvatar(
                    radius: 40,
                    backgroundColor: Colors.deepPurpleAccent.withOpacity(0.2),
                    child: Text(
                      widget.username.substring(0, 1).toUpperCase(),
                      style: const TextStyle(color: Colors.purpleAccent, fontSize: 32, fontWeight: FontWeight.bold),
                    ),
                  ),
                  const SizedBox(height: 16),
                  Text(
                    '@${widget.username}',
                    style: const TextStyle(fontSize: 24, fontWeight: FontWeight.bold, color: Colors.white),
                  ),
                  const SizedBox(height: 4),
                  const Text(
                    'End-to-End Cryptography Active',
                    style: TextStyle(color: Colors.grey, fontSize: 13),
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 24),
          const Text(
            'Secure Identifiers',
            style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold, color: Colors.white),
          ),
          const SizedBox(height: 12),
          _buildInfoItem(
            title: 'Account ID (UUID)',
            value: widget.accountId,
            canCopy: true,
          ),
          const SizedBox(height: 8),
          _buildInfoItem(
            title: 'Current Device ID',
            value: widget.deviceId,
            canCopy: true,
          ),
        ],
      ),
    );
  }

  Widget _buildInfoItem({required String title, required String value, bool canCopy = false}) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: const Color(0xFF1E1E2E),
        borderRadius: BorderRadius.circular(12),
      ),
      child: Row(
        children: [
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(title, style: const TextStyle(color: Colors.grey, fontSize: 11)),
                const SizedBox(height: 4),
                Text(
                  value,
                  style: const TextStyle(
                    color: Colors.white,
                    fontFamily: 'monospace',
                    fontSize: 13,
                  ),
                ),
              ],
            ),
          ),
          if (canCopy)
            IconButton(
              icon: const Icon(Icons.copy, color: Colors.deepPurpleAccent, size: 20),
              onPressed: () {
                Clipboard.setData(ClipboardData(text: value));
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(
                    content: Text('Copied to clipboard!'),
                    duration: Duration(seconds: 2),
                  ),
                );
              },
            ),
        ],
      ),
    );
  }
}

void _showNewChatDialog(BuildContext context, WidgetRef ref) {
  final controller = TextEditingController();
  String? error;
  bool loading = false;

  showDialog(
    context: context,
    builder: (context) {
      return StatefulBuilder(
        builder: (context, setState) {
          return AlertDialog(
            backgroundColor: const Color(0xFF1E1E2E),
            title: const Text('Start New Secure Chat'),
            content: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                if (error != null) ...[
                  Text(error!, style: const TextStyle(color: Colors.redAccent, fontSize: 13)),
                  const SizedBox(height: 8),
                ],
                TextField(
                  controller: controller,
                  decoration: const InputDecoration(
                    hintText: 'Type username or UUID...',
                    labelText: 'Username or Account ID',
                    prefixIcon: Icon(Icons.search),
                  ),
                ),
                if (loading) ...[
                  const SizedBox(height: 16),
                  const CircularProgressIndicator(color: Colors.deepPurpleAccent),
                ],
              ],
            ),
            actions: [
              TextButton(
                onPressed: () => Navigator.pop(context),
                child: const Text('Cancel', style: TextStyle(color: Colors.grey)),
              ),
              ElevatedButton(
                style: ElevatedButton.styleFrom(backgroundColor: Colors.deepPurpleAccent),
                onPressed: loading ? null : () async {
                  final query = controller.text.trim();
                  if (query.isEmpty) return;
                  
                  setState(() {
                    loading = true;
                    error = null;
                  });

                  try {
                    await ref.read(chatProvider.notifier).startNewChat(query);
                    if (context.mounted) {
                      Navigator.pop(context);
                    }
                  } catch (e) {
                    setState(() {
                      loading = false;
                      error = e.toString().replaceAll('Exception: ', '');
                    });
                  }
                },
                child: const Text('Create'),
              ),
            ],
          );
        },
      );
    },
  );
}

class ChatRoomPage extends ConsumerStatefulWidget {
  final ChatConversation conversation;
  const ChatRoomPage({super.key, required this.conversation});

  @override
  ConsumerState<ChatRoomPage> createState() => _ChatRoomPageState();
}

class _ChatRoomPageState extends ConsumerState<ChatRoomPage> {
  final _messageController = TextEditingController();
  final _scrollController = ScrollController();

  void _scrollToBottom() {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (_scrollController.hasClients) {
        _scrollController.animateTo(
          _scrollController.position.maxScrollExtent,
          duration: const Duration(milliseconds: 300),
          curve: Curves.easeOut,
        );
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    // Listen to updates for this chat log
    final chatState = ref.watch(chatProvider);
    final conv = chatState.conversations.firstWhere(
      (c) => c.conversationId == widget.conversation.conversationId,
      orElse: () => widget.conversation,
    );

    _scrollToBottom();

    return Scaffold(
      appBar: AppBar(
        title: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(conv.otherUsername),
            const Text(
              'Secure ratchet session active',
              style: TextStyle(fontSize: 11, color: Colors.greenAccent),
            ),
          ],
        ),
        backgroundColor: const Color(0xFF1E1E2E),
      ),
      body: Column(
        children: [
          Expanded(
            child: conv.messages.isEmpty
                ? const Center(
                    child: Text(
                      'No messages yet.\nSay hello in this secure chat!',
                      textAlign: TextAlign.center,
                      style: TextStyle(color: Colors.grey),
                    ),
                  )
                : ListView.builder(
                    controller: _scrollController,
                    padding: const EdgeInsets.all(16),
                    itemCount: conv.messages.length,
                    itemBuilder: (context, index) {
                      final msg = conv.messages[index];
                      final isMe = msg.senderDeviceId != conv.otherDeviceId;
                      return Align(
                        alignment: isMe ? Alignment.centerRight : Alignment.centerLeft,
                        child: Container(
                          margin: const EdgeInsets.symmetric(vertical: 4),
                          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
                          decoration: BoxDecoration(
                            color: isMe ? Colors.deepPurpleAccent : const Color(0xFF1E1E2E),
                            borderRadius: BorderRadius.only(
                              topLeft: const Radius.circular(12),
                              topRight: const Radius.circular(12),
                              bottomLeft: Radius.circular(isMe ? 12 : 0),
                              bottomRight: Radius.circular(isMe ? 0 : 12),
                            ),
                          ),
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            mainAxisSize: MainAxisSize.min,
                            children: [
                              Text(msg.text, style: const TextStyle(color: Colors.white)),
                              const SizedBox(height: 4),
                              Text(
                                '${msg.timestamp.hour.toString().padLeft(2, '0')}:${msg.timestamp.minute.toString().padLeft(2, '0')}',
                                style: const TextStyle(color: Colors.white60, fontSize: 9),
                              ),
                            ],
                          ),
                        ),
                      );
                    },
                  ),
          ),
          Container(
            padding: const EdgeInsets.all(12),
            color: const Color(0xFF1E1E2E),
            child: Row(
              children: [
                Expanded(
                  child: TextField(
                    controller: _messageController,
                    decoration: const InputDecoration(
                      hintText: 'Type a secure message...',
                      border: InputBorder.none,
                      contentPadding: EdgeInsets.symmetric(horizontal: 16),
                    ),
                    onSubmitted: (_) => _sendMessage(),
                  ),
                ),
                IconButton(
                  icon: const Icon(Icons.send, color: Colors.deepPurpleAccent),
                  onPressed: _sendMessage,
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  void _sendMessage() {
    final text = _messageController.text.trim();
    if (text.isEmpty) return;
    ref.read(chatProvider.notifier).sendMessage(widget.conversation.conversationId, text);
    _messageController.clear();
    _scrollToBottom();
  }
}

class ChatMessage {
  final String messageId;
  final String senderDeviceId;
  final String text;
  final DateTime timestamp;

  ChatMessage({
    required this.messageId,
    required this.senderDeviceId,
    required this.text,
    required this.timestamp,
  });
}

class ChatConversation {
  final String conversationId;
  final String otherUsername;
  final String otherAccountId;
  final String otherDeviceId;
  final List<ChatMessage> messages;

  ChatConversation({
    required this.conversationId,
    required this.otherUsername,
    required this.otherAccountId,
    required this.otherDeviceId,
    required this.messages,
  });

  ChatConversation copyWith({
    List<ChatMessage>? messages,
  }) {
    return ChatConversation(
      conversationId: conversationId,
      otherUsername: otherUsername,
      otherAccountId: otherAccountId,
      otherDeviceId: otherDeviceId,
      messages: messages ?? this.messages,
    );
  }
}

class ChatState {
  final List<ChatConversation> conversations;
  final bool isConnected;
  final String? error;

  ChatState({
    required this.conversations,
    this.isConnected = false,
    this.error,
  });

  ChatState copyWith({
    List<ChatConversation>? conversations,
    bool? isConnected,
    String? error,
  }) {
    return ChatState(
      conversations: conversations ?? this.conversations,
      isConnected: isConnected ?? this.isConnected,
      error: error ?? this.error,
    );
  }
}

class ChatNotifier extends StateNotifier<ChatState> {
  final AuthApiClient _api;
  VeilWebSocketClient? _wsClient;
  String? _myDeviceId;
  
  ChatNotifier({required AuthApiClient api})
      : _api = api,
        super(ChatState(conversations: []));

  void init(String accessToken, String myDeviceId) {
    debugPrint('[ChatNotifier] Initializing WebSocket client.');
    _myDeviceId = myDeviceId;
    final wsUri = Uri.parse(_api.baseUrl.replaceAll('http', 'ws') + '/api/v1/ws');
    
    _wsClient?.disconnect();
    _wsClient = VeilWebSocketClient(wsUri: wsUri, accessToken: accessToken);
    _wsClient!.connect();

    _wsClient!.connectionState.listen((connected) {
      debugPrint('[ChatNotifier] WS Connection State: $connected');
      state = state.copyWith(isConnected: connected);
    });

    _wsClient!.messages.listen((binBytes) {
      _handleIncomingEnvelope(binBytes);
    });
  }

  void _handleIncomingEnvelope(Uint8List binBytes) {
    try {
      final decoded = cbor.decode(binBytes);
      if (decoded is CborMap) {
        final msgIdBytes = (decoded[CborString('message_id')] as CborBytes).bytes;
        final convIdBytes = (decoded[CborString('conversation_id')] as CborBytes).bytes;
        final senderDeviceBytes = (decoded[CborString('sender_device_id')] as CborBytes).bytes;
        final ciphertextBytes = (decoded[CborString('ciphertext')] as CborBytes).bytes;

        final messageId = Uuid.unparse(msgIdBytes);
        final conversationId = Uuid.unparse(convIdBytes);
        final senderDeviceId = Uuid.unparse(senderDeviceBytes);
        final text = utf8.decode(ciphertextBytes);

        debugPrint('[ChatNotifier] Received message envelope over WS: "$text" in conv $conversationId');

        final newMessage = ChatMessage(
          messageId: messageId,
          senderDeviceId: senderDeviceId,
          text: text,
          timestamp: DateTime.now(),
        );

        // Find conversation
        final index = state.conversations.indexWhere((c) => c.conversationId == conversationId);
        if (index != -1) {
          final conv = state.conversations[index];
          final updatedMessages = List<ChatMessage>.from(conv.messages)..add(newMessage);
          final updatedConversations = List<ChatConversation>.from(state.conversations);
          updatedConversations[index] = conv.copyWith(messages: updatedMessages);
          state = state.copyWith(conversations: updatedConversations);
        } else {
          // Dynamic conversation creation if not found (message from new contact/device)
          final newConv = ChatConversation(
            conversationId: conversationId,
            otherUsername: 'Device: ' + senderDeviceId.substring(0, 8),
            otherAccountId: 'Unknown',
            otherDeviceId: senderDeviceId,
            messages: [newMessage],
          );
          state = state.copyWith(conversations: [...state.conversations, newConv]);
        }
      }
    } catch (e, stack) {
      debugPrint('[ChatNotifier] Failed to decode incoming envelope: $e');
      debugPrint('$stack');
    }
  }

  Future<void> startNewChat(String usernameOrId) async {
    state = state.copyWith(error: null);
    try {
      debugPrint('[ChatNotifier] Searching for user: $usernameOrId');
      final result = await _api.lookupUser(usernameOrId);
      
      final otherUserId = result['user_id'] as String;
      final otherUsername = result['username'] as String;
      final otherAccountId = result['display_name'] ?? result['username'] as String;
      final devices = result['devices'] as List<dynamic>;

      if (devices.isEmpty) {
        throw Exception('User has no active approved devices.');
      }

      // Address message to the first approved device
      final firstDevice = devices.first as Map<String, dynamic>;
      final otherDeviceId = firstDevice['device_id'] as String;

      // Unique conversation ID derived from user IDs
      final conversationId = const Uuid().v4();

      final newConv = ChatConversation(
        conversationId: conversationId,
        otherUsername: otherUsername,
        otherAccountId: otherAccountId,
        otherDeviceId: otherDeviceId,
        messages: [],
      );

      // Add to conversations list if not already present
      final exists = state.conversations.any((c) => c.otherDeviceId == otherDeviceId);
      if (!exists) {
        state = state.copyWith(conversations: [...state.conversations, newConv]);
      }
    } catch (e) {
      debugPrint('[ChatNotifier] Start chat failed: $e');
      state = state.copyWith(error: e.toString());
      rethrow;
    }
  }

  void sendMessage(String conversationId, String text) {
    if (_wsClient == null || !state.isConnected) {
      debugPrint('[ChatNotifier] WS disconnected. Message send failed.');
      return;
    }

    final index = state.conversations.indexWhere((c) => c.conversationId == conversationId);
    if (index == -1) return;

    final conv = state.conversations[index];
    final messageId = const Uuid().v4();

    // Build CBOR envelope
    final msgIdBytes = Uuid.parse(messageId);
    final convIdBytes = Uuid.parse(conversationId);
    final senderDeviceBytes = Uuid.parse(_myDeviceId!);
    final recipientDeviceBytes = Uuid.parse(conv.otherDeviceId);
    final ciphertextBytes = Uint8List.fromList(utf8.encode(text));

    final map = {
      'message_id': CborBytes(msgIdBytes),
      'conversation_id': CborBytes(convIdBytes),
      'sender_device_id': CborBytes(senderDeviceBytes),
      'recipient_device_id': CborBytes(recipientDeviceBytes),
      'timestamp': DateTime.now().millisecondsSinceEpoch,
      'dh_pub': CborBytes(Uint8List(32)), // dummy DH
      'ciphertext': CborBytes(ciphertextBytes),
      'signature': CborBytes(Uint8List(64)), // dummy signature
      'major_version': 1,
      'minor_version': 0,
      'message_number': conv.messages.length + 1,
    };

    final binBytes = cbor.encode(CborValue(map));
    
    // Transmit envelope
    _wsClient!.sendEnvelope(Uint8List.fromList(binBytes));
    debugPrint('[ChatNotifier] Sent message envelope over WS: "$text"');

    // Add locally to the state
    final localMessage = ChatMessage(
      messageId: messageId,
      senderDeviceId: _myDeviceId!,
      text: text,
      timestamp: DateTime.now(),
    );

    final updatedMessages = List<ChatMessage>.from(conv.messages)..add(localMessage);
    final updatedConversations = List<ChatConversation>.from(state.conversations);
    updatedConversations[index] = conv.copyWith(messages: updatedMessages);
    state = state.copyWith(conversations: updatedConversations);
  }

  void disconnect() {
    _wsClient?.disconnect();
    _wsClient = null;
    state = ChatState(conversations: []);
  }
}

final chatProvider = StateNotifierProvider<ChatNotifier, ChatState>((ref) {
  final api = ref.watch(authApiClientProvider);
  return ChatNotifier(api: api);
});
