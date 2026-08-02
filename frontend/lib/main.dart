// frontend/lib/main.dart

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:cbor/cbor.dart';
import 'package:uuid/uuid.dart';
import 'package:cryptography/cryptography.dart';

import 'package:image_picker/image_picker.dart';
import 'package:file_picker/file_picker.dart';
import 'package:path_provider/path_provider.dart';
import 'package:record/record.dart';
import 'package:audioplayers/audioplayers.dart';
import 'package:permission_handler/permission_handler.dart';
import 'package:open_filex/open_filex.dart';
import 'package:flutter_webrtc/flutter_webrtc.dart';

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
      home: Stack(
        children: [
          const AuthRouter(),
          const CallOverlayWrapper(),
        ],
      ),
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
        onPressed: () => _showNewActionSheet(context),
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

  void _showNewActionSheet(BuildContext context) {
    showModalBottomSheet(
      context: context,
      backgroundColor: const Color(0xFF1E1E2E),
      builder: (context) {
        return SafeArea(
          child: Wrap(
            children: [
              ListTile(
                leading: const Icon(Icons.person_add, color: Colors.deepPurpleAccent),
                title: const Text('Start 1-to-1 secure chat', style: TextStyle(color: Colors.white)),
                onTap: () {
                  Navigator.pop(context);
                  _showNewChatDialog(context, ref);
                },
              ),
              ListTile(
                leading: const Icon(Icons.group_add, color: Colors.deepPurpleAccent),
                title: const Text('Create group chat', style: TextStyle(color: Colors.white)),
                onTap: () {
                  Navigator.pop(context);
                  _showNewGroupDialog(context, ref);
                },
              ),
            ],
          ),
        );
      },
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

  // Media upload progress state
  double? _uploadProgress;
  String? _uploadStatusText;

  // Real voice message recording variables
  final _audioRecorder = AudioRecorder();
  bool _isRecording = false;
  bool _isRecordPaused = false;
  bool _isRecordLocked = false;
  String? _recordFilePath;
  int _recordDuration = 0;
  Timer? _recordTimer;
  Timer? _waveformTimer;
  List<double> _amplitudeHistory = [];

  // Real voice playback variables (Single shared player)
  late AudioPlayer _voicePlayer;
  String? _playingVoiceMsgId;
  bool _isVoicePlaying = false;
  Duration _voicePosition = Duration.zero;
  Duration _voiceDuration = Duration.zero;
  double _playbackSpeed = 1.0;
  
  StreamSubscription? _posSub;
  StreamSubscription? _durSub;
  StreamSubscription? _stateSub;

  @override
  void initState() {
    super.initState();
    _voicePlayer = AudioPlayer();
    _posSub = _voicePlayer.onPositionChanged.listen((pos) {
      setState(() {
        _voicePosition = pos;
      });
    });
    _durSub = _voicePlayer.onDurationChanged.listen((dur) {
      setState(() {
        _voiceDuration = dur;
      });
    });
    _stateSub = _voicePlayer.onPlayerStateChanged.listen((pState) {
      setState(() {
        _isVoicePlaying = pState == PlayerState.playing;
      });
    });
  }

  @override
  void dispose() {
    _recordTimer?.cancel();
    _waveformTimer?.cancel();
    _posSub?.cancel();
    _durSub?.cancel();
    _stateSub?.cancel();
    _voicePlayer.dispose();
    _audioRecorder.dispose();
    _messageController.dispose();
    _scrollController.dispose();
    super.dispose();
  }

  Future<void> _startRecording() async {
    try {
      if (await _audioRecorder.hasPermission()) {
        final dir = await getTemporaryDirectory();
        final path = '${dir.path}/voice_${DateTime.now().millisecondsSinceEpoch}.m4a';
        _recordFilePath = path;

        await _audioRecorder.start(
          const RecordConfig(encoder: AudioEncoder.aacLc),
          path: path,
        );

        _recordDuration = 0;
        _amplitudeHistory.clear();
        _recordTimer?.cancel();
        _recordTimer = Timer.periodic(const Duration(seconds: 1), (timer) {
          setState(() {
            _recordDuration++;
          });
        });

        _waveformTimer?.cancel();
        _waveformTimer = Timer.periodic(const Duration(milliseconds: 100), (timer) async {
          final amp = await _audioRecorder.getAmplitude();
          setState(() {
            double level = (amp.current + 160) / 160;
            if (level < 0) level = 0.05;
            if (level > 1) level = 1.0;
            _amplitudeHistory.add(level);
            if (_amplitudeHistory.length > 40) {
              _amplitudeHistory.removeAt(0);
            }
          });
        });

        setState(() {
          _isRecording = true;
          _isRecordPaused = false;
          _isRecordLocked = false;
        });
      }
    } catch (e) {
      debugPrint('[VoiceRecorder] Error starting record: $e');
    }
  }

  Future<void> _pauseRecording() async {
    await _audioRecorder.pause();
    _recordTimer?.cancel();
    _waveformTimer?.cancel();
    setState(() {
      _isRecordPaused = true;
    });
  }

  Future<void> _resumeRecording() async {
    await _audioRecorder.resume();
    _recordTimer = Timer.periodic(const Duration(seconds: 1), (timer) {
      setState(() {
        _recordDuration++;
      });
    });
    _waveformTimer = Timer.periodic(const Duration(milliseconds: 100), (timer) async {
      final amp = await _audioRecorder.getAmplitude();
      setState(() {
        double level = (amp.current + 160) / 160;
        if (level < 0) level = 0.05;
        if (level > 1) level = 1.0;
        _amplitudeHistory.add(level);
        if (_amplitudeHistory.length > 40) {
          _amplitudeHistory.removeAt(0);
        }
      });
    });
    setState(() {
      _isRecordPaused = false;
    });
  }

  Future<void> _stopAndSendRecording() async {
    _recordTimer?.cancel();
    _waveformTimer?.cancel();
    final path = await _audioRecorder.stop();
    setState(() {
      _isRecording = false;
      _isRecordLocked = false;
      _isRecordPaused = false;
    });

    if (path != null && _recordDuration > 0) {
      try {
        final file = File(path);
        final bytes = await file.readAsBytes();

        setState(() {
          _uploadProgress = 0.0;
          _uploadStatusText = 'Encrypting & uploading voice note...';
        });

        final authState = ref.read(authProvider);
        if (authState is! AuthSuccess) return;
        final sessionToken = authState.session.accessToken;

        await ref.read(chatProvider.notifier).sendMediaMessage(
          sessionToken: sessionToken,
          conversationId: widget.conversation.conversationId,
          type: 'voice',
          filename: 'voice_${DateTime.now().millisecondsSinceEpoch}.m4a',
          mimeType: 'audio/m4a',
          fileBytes: bytes,
          durationSeconds: _recordDuration,
          onProgress: (progress) {
            setState(() {
              _uploadProgress = progress;
              _uploadStatusText = 'Uploading voice note (${(progress * 100).toInt()}%)...';
            });
          },
        );
      } catch (e) {
        debugPrint('[VoiceRecorder] Error sending voice note: $e');
      } finally {
        setState(() {
          _uploadProgress = null;
          _uploadStatusText = null;
        });
      }
    }
  }

  Future<void> _cancelRecording() async {
    _recordTimer?.cancel();
    _waveformTimer?.cancel();
    await _audioRecorder.stop();
    setState(() {
      _isRecording = false;
      _isRecordLocked = false;
      _isRecordPaused = false;
    });
    if (_recordFilePath != null) {
      try {
        final file = File(_recordFilePath!);
        if (await file.exists()) {
          await file.delete();
        }
      } catch (_) {}
    }
  }

  void _toggleVoicePlayback(ChatMessage msg) async {
    if (_playingVoiceMsgId == msg.messageId) {
      if (_isVoicePlaying) {
        await _voicePlayer.pause();
      } else {
        await _voicePlayer.resume();
      }
    } else {
      await _voicePlayer.stop();
      setState(() {
        _playingVoiceMsgId = msg.messageId;
        _voicePosition = Duration.zero;
        _voiceDuration = Duration.zero;
      });
      if (msg.decryptedData != null) {
        await _voicePlayer.setPlaybackRate(_playbackSpeed);
        await _voicePlayer.play(BytesSource(msg.decryptedData!));
      }
    }
  }

  void _cyclePlaybackSpeed() async {
    double nextSpeed = 1.0;
    if (_playbackSpeed == 1.0) {
      nextSpeed = 1.5;
    } else if (_playbackSpeed == 1.5) {
      nextSpeed = 2.0;
    } else {
      nextSpeed = 1.0;
    }
    setState(() {
      _playbackSpeed = nextSpeed;
    });
    if (_isVoicePlaying) {
      await _voicePlayer.setPlaybackRate(nextSpeed);
    }
  }

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

  Widget _buildMessageContent(ChatMessage msg, ChatConversation conv, String sessionToken) {
    if (msg.type == 'image') {
      if (msg.decryptedData != null) {
        return Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            GestureDetector(
              onTap: () => _openImageFullScreen(msg),
              child: ClipRRect(
                borderRadius: BorderRadius.circular(8),
                child: Image.memory(
                  msg.decryptedData!,
                  width: 220,
                  height: 180,
                  fit: BoxFit.cover,
                  errorBuilder: (context, error, stackTrace) => Container(
                    width: 220,
                    height: 180,
                    color: Colors.white12,
                    child: const Center(
                      child: Icon(Icons.broken_image, color: Colors.white60, size: 40),
                    ),
                  ),
                ),
              ),
            ),
            const SizedBox(height: 6),
            Text(
              msg.filename ?? 'image.png',
              style: const TextStyle(fontSize: 12, fontWeight: FontWeight.w500),
            ),
            Text(
              '${(msg.fileSize ?? 0) ~/ 1024} KB',
              style: const TextStyle(fontSize: 10, color: Colors.white60),
            ),
          ],
        );
      } else if (msg.isDownloading) {
        return const SizedBox(
          width: 200,
          height: 80,
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              SizedBox(
                width: 24,
                height: 24,
                child: CircularProgressIndicator(strokeWidth: 2.0, color: Colors.white),
              ),
              SizedBox(height: 8),
              Text(
                'Downloading & Decrypting...',
                style: TextStyle(fontSize: 11, color: Colors.white70),
              ),
            ],
          ),
        );
      } else {
        return InkWell(
          onTap: () => ref.read(chatProvider.notifier).downloadMedia(
            sessionToken: sessionToken,
            conversationId: conv.conversationId,
            messageId: msg.messageId,
            blobId: msg.blobId!,
          ),
          child: Container(
            width: 200,
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: Colors.white10,
              borderRadius: BorderRadius.circular(8),
            ),
            child: Row(
              children: [
                const Icon(Icons.image, color: Colors.purpleAccent, size: 36),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        msg.filename ?? 'image.png',
                        style: const TextStyle(fontSize: 12, fontWeight: FontWeight.bold),
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                      Text(
                        'Tap to download • ${(msg.fileSize ?? 0) ~/ 1024} KB',
                        style: const TextStyle(fontSize: 10, color: Colors.white60),
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),
        );
      }
    } else if (msg.type == 'file') {
      if (msg.decryptedData != null) {
        return InkWell(
          onTap: () => _openFile(msg),
          child: Container(
            width: 220,
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(
              color: Colors.green.withOpacity(0.15),
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: Colors.green.withOpacity(0.3)),
            ),
            child: Row(
              children: [
                const Icon(Icons.file_present, color: Colors.greenAccent, size: 32),
                const SizedBox(width: 10),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        msg.filename ?? 'document.pdf',
                        style: const TextStyle(fontSize: 12, fontWeight: FontWeight.bold),
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                      Text(
                        'Tap to Open • ${(msg.fileSize ?? 0) ~/ 1024} KB',
                        style: const TextStyle(fontSize: 10, color: Colors.white60),
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),
        );
      } else if (msg.isDownloading) {
        return const SizedBox(
          width: 200,
          height: 60,
          child: Row(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              SizedBox(
                width: 20,
                height: 20,
                child: CircularProgressIndicator(strokeWidth: 2.0, color: Colors.white),
              ),
              SizedBox(width: 12),
              Text(
                'Downloading File...',
                style: TextStyle(fontSize: 11, color: Colors.white70),
              ),
            ],
          ),
        );
      } else {
        return InkWell(
          onTap: () => ref.read(chatProvider.notifier).downloadMedia(
            sessionToken: sessionToken,
            conversationId: conv.conversationId,
            messageId: msg.messageId,
            blobId: msg.blobId!,
          ),
          child: Container(
            width: 200,
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: Colors.white10,
              borderRadius: BorderRadius.circular(8),
            ),
            child: Row(
              children: [
                const Icon(Icons.insert_drive_file, color: Colors.blueAccent, size: 36),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        msg.filename ?? 'document.pdf',
                        style: const TextStyle(fontSize: 12, fontWeight: FontWeight.bold),
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                      Text(
                        'Tap to download • ${(msg.fileSize ?? 0) ~/ 1024} KB',
                        style: const TextStyle(fontSize: 10, color: Colors.white60),
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),
        );
      }
    } else if (msg.type == 'voice') {
      final isPlaying = _playingVoiceMsgId == msg.messageId;
      final currentPos = isPlaying ? _voicePosition.inSeconds : 0;
      final duration = msg.durationSeconds ?? (isPlaying && _voiceDuration.inSeconds > 0 ? _voiceDuration.inSeconds : 5);
      
      if (msg.isDownloading) {
        return const SizedBox(
          width: 180,
          height: 44,
          child: Row(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              SizedBox(
                width: 16,
                height: 16,
                child: CircularProgressIndicator(strokeWidth: 1.5, color: Colors.white),
              ),
              SizedBox(width: 10),
              Text('Fetching audio...', style: TextStyle(fontSize: 11, color: Colors.white70)),
            ],
          ),
        );
      }
      
      return Container(
        width: 250,
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 6),
        decoration: BoxDecoration(
          color: Colors.white.withOpacity(0.06),
          borderRadius: BorderRadius.circular(8),
        ),
        child: Row(
          children: [
            IconButton(
              icon: Icon(
                (isPlaying && _isVoicePlaying) ? Icons.pause_circle_filled : Icons.play_circle_filled,
                color: Colors.purpleAccent,
                size: 32,
              ),
              padding: EdgeInsets.zero,
              constraints: const BoxConstraints(),
              onPressed: () {
                if (msg.decryptedData == null) {
                  ref.read(chatProvider.notifier).downloadMedia(
                    sessionToken: sessionToken,
                    conversationId: conv.conversationId,
                    messageId: msg.messageId,
                    blobId: msg.blobId!,
                  );
                } else {
                  _toggleVoicePlayback(msg);
                }
              },
            ),
            const SizedBox(width: 4),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  SliderTheme(
                    data: SliderTheme.of(context).copyWith(
                      thumbShape: const RoundSliderThumbShape(enabledThumbRadius: 4),
                      overlayShape: const RoundSliderOverlayShape(overlayRadius: 8),
                      trackHeight: 2,
                      activeTrackColor: Colors.purpleAccent,
                      inactiveTrackColor: Colors.white24,
                      thumbColor: Colors.purpleAccent,
                    ),
                    child: Slider(
                      value: currentPos.toDouble().clamp(0.0, duration.toDouble()),
                      min: 0,
                      max: duration.toDouble(),
                      onChanged: (val) {
                        if (isPlaying && msg.decryptedData != null) {
                          _voicePlayer.seek(Duration(seconds: val.toInt()));
                        }
                      },
                    ),
                  ),
                  Padding(
                    padding: const EdgeInsets.symmetric(horizontal: 8),
                    child: Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: [
                        Text(
                          '0:${currentPos.toString().padLeft(2, '0')}',
                          style: const TextStyle(fontSize: 9, color: Colors.white60),
                        ),
                        Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            if (isPlaying) ...[
                              GestureDetector(
                                onTap: _cyclePlaybackSpeed,
                                child: Container(
                                  padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 1),
                                  decoration: BoxDecoration(
                                    color: Colors.white12,
                                    borderRadius: BorderRadius.circular(4),
                                  ),
                                  child: Text(
                                    '${_playbackSpeed}x',
                                    style: const TextStyle(fontSize: 8, fontWeight: FontWeight.bold, color: Colors.purpleAccent),
                                  ),
                                ),
                              ),
                              const SizedBox(width: 8),
                            ],
                            Text(
                              '0:${duration.toString().padLeft(2, '0')}',
                              style: const TextStyle(fontSize: 9, color: Colors.white60),
                            ),
                          ],
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
      );
    }
    
    return Text(msg.text, style: const TextStyle(color: Colors.white));
  }

  Future<void> _openFile(ChatMessage msg) async {
    if (msg.decryptedData == null) return;
    try {
      final dir = await getTemporaryDirectory();
      final path = '${dir.path}/${msg.filename ?? 'document.pdf'}';
      final file = File(path);
      await file.writeAsBytes(msg.decryptedData!);
      await OpenFilex.open(path);
    } catch (e) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Could not open file: $e')),
      );
    }
  }

  void _openImageFullScreen(ChatMessage msg) {
    if (msg.decryptedData == null) return;
    Navigator.push(
      context,
      MaterialPageRoute(
        builder: (context) => Scaffold(
          backgroundColor: Colors.black,
          appBar: AppBar(
            backgroundColor: Colors.black,
            actions: [
              IconButton(
                icon: const Icon(Icons.download, color: Colors.white),
                onPressed: () async {
                  try {
                    final dir = await getExternalStorageDirectory() ?? await getApplicationDocumentsDirectory();
                    final path = '${dir.path}/${msg.filename ?? 'image.png'}';
                    final file = File(path);
                    await file.writeAsBytes(msg.decryptedData!);
                    if (context.mounted) {
                      ScaffoldMessenger.of(context).showSnackBar(
                        SnackBar(content: Text('Saved to: $path')),
                      );
                    }
                  } catch (e) {
                    ScaffoldMessenger.of(context).showSnackBar(
                      SnackBar(content: Text('Failed to save image: $e')),
                    );
                  }
                },
              ),
            ],
          ),
          body: Center(
            child: InteractiveViewer(
              clipBehavior: Clip.none,
              minScale: 0.5,
              maxScale: 4.0,
              child: Image.memory(msg.decryptedData!),
            ),
          ),
        ),
      ),
    );
  }

  void _showAttachmentMenu() {
    showModalBottomSheet(
      context: context,
      backgroundColor: const Color(0xFF1E1E2E),
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(16)),
      ),
      builder: (context) {
        return SafeArea(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Container(
                margin: const EdgeInsets.symmetric(vertical: 8),
                width: 40,
                height: 4,
                decoration: BoxDecoration(
                  color: Colors.white24,
                  borderRadius: BorderRadius.circular(2),
                ),
              ),
              const Padding(
                padding: EdgeInsets.symmetric(vertical: 8),
                child: Text(
                  'Send Encrypted Attachment',
                  style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16),
                ),
              ),
              const Divider(color: Colors.white12),
              ListTile(
                leading: const CircleAvatar(
                  backgroundColor: Colors.purple,
                  child: Icon(Icons.image, color: Colors.white),
                ),
                title: const Text('Share Photo from Gallery'),
                subtitle: const Text('Pick a secure image using native library', style: TextStyle(fontSize: 11, color: Colors.white54)),
                onTap: () {
                  Navigator.pop(context);
                  _pickAndSendImage(ImageSource.gallery);
                },
              ),
              ListTile(
                leading: const CircleAvatar(
                  backgroundColor: Colors.teal,
                  child: Icon(Icons.camera_alt, color: Colors.white),
                ),
                title: const Text('Take Secure Photo'),
                subtitle: const Text('Launch native hardware camera safely', style: TextStyle(fontSize: 11, color: Colors.white54)),
                onTap: () {
                  Navigator.pop(context);
                  _pickAndSendImage(ImageSource.camera);
                },
              ),
              ListTile(
                leading: const CircleAvatar(
                  backgroundColor: Colors.blue,
                  child: Icon(Icons.insert_drive_file, color: Colors.white),
                ),
                title: const Text('Share Encrypted Document'),
                subtitle: const Text('Select ZIP, PDF, or APK using native explorer', style: TextStyle(fontSize: 11, color: Colors.white54)),
                onTap: () {
                  Navigator.pop(context);
                  _pickAndSendFile();
                },
              ),
              ListTile(
                leading: const CircleAvatar(
                  backgroundColor: Colors.red,
                  child: Icon(Icons.mic, color: Colors.white),
                ),
                title: const Text('Record Voice Note'),
                subtitle: const Text('Triggers real-time microphone hardware feed', style: TextStyle(fontSize: 11, color: Colors.white54)),
                onTap: () {
                  Navigator.pop(context);
                  _startRecording();
                },
              ),
              const SizedBox(height: 12),
            ],
          ),
        );
      },
    );
  }

  void _pickAndSendImage(ImageSource source) async {
    try {
      final picker = ImagePicker();
      final XFile? image = await picker.pickImage(source: source);
      if (image == null) return;

      final bytes = await image.readAsBytes();
      final filename = image.name;
      final mimeType = 'image/png';

      setState(() {
        _uploadProgress = 0.0;
        _uploadStatusText = 'Encrypting & preparing image...';
      });

      final authState = ref.read(authProvider);
      if (authState is! AuthSuccess) return;
      final sessionToken = authState.session.accessToken;

      await ref.read(chatProvider.notifier).sendMediaMessage(
        sessionToken: sessionToken,
        conversationId: widget.conversation.conversationId,
        type: 'image',
        filename: filename,
        mimeType: mimeType,
        fileBytes: bytes,
        onProgress: (progress) {
          setState(() {
            _uploadProgress = progress;
            _uploadStatusText = 'Uploading image chunks (${(progress * 100).toInt()}%)...';
          });
        },
      );
    } catch (e) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Failed to pick/send image: $e')),
      );
    } finally {
      setState(() {
        _uploadProgress = null;
        _uploadStatusText = null;
      });
    }
  }

  void _pickAndSendFile() async {
    try {
      final result = await FilePicker.platform.pickFiles();
      if (result == null || result.files.single.path == null) return;

      final file = result.files.single;
      final bytes = await File(file.path!).readAsBytes();
      final filename = file.name;
      final mimeType = file.extension != null ? 'application/${file.extension}' : 'application/octet-stream';

      setState(() {
        _uploadProgress = 0.0;
        _uploadStatusText = 'Encrypting & preparing file...';
      });

      final authState = ref.read(authProvider);
      if (authState is! AuthSuccess) return;
      final sessionToken = authState.session.accessToken;

      await ref.read(chatProvider.notifier).sendMediaMessage(
        sessionToken: sessionToken,
        conversationId: widget.conversation.conversationId,
        type: 'file',
        filename: filename,
        mimeType: mimeType,
        fileBytes: bytes,
        onProgress: (progress) {
          setState(() {
            _uploadProgress = progress;
            _uploadStatusText = 'Uploading file chunks (${(progress * 100).toInt()}%)...';
          });
        },
      );
    } catch (e) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Failed to pick/send file: $e')),
      );
    } finally {
      setState(() {
        _uploadProgress = null;
        _uploadStatusText = null;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    // Listen to updates for this chat log
    final chatState = ref.watch(chatProvider);
    final conv = chatState.conversations.firstWhere(
      (c) => c.conversationId == widget.conversation.conversationId,
      orElse: () => widget.conversation,
    );

    final authState = ref.watch(authProvider);
    String myDeviceId = '';
    String sessionToken = '';
    if (authState is AuthSuccess) {
      myDeviceId = authState.credentials.deviceId;
      sessionToken = authState.session.accessToken;
    }

    _scrollToBottom();

    return Scaffold(
      appBar: AppBar(
        title: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(conv.otherUsername),
            Text(
              conv.isGroup ? 'Group Chat (${conv.groupMemberUsernames.length} members)' : 'Secure ratchet session active',
              style: const TextStyle(fontSize: 11, color: Colors.greenAccent),
            ),
          ],
        ),
        backgroundColor: const Color(0xFF1E1E2E),
        actions: [
          if (!conv.isGroup) ...[
            IconButton(
              icon: const Icon(Icons.call, color: Colors.purpleAccent),
              onPressed: () {
                ref.read(callStateProvider.notifier).startCall(
                  conversationId: conv.conversationId,
                  otherUsername: conv.otherUsername,
                  otherDeviceId: conv.otherDeviceId,
                  isVideo: false,
                );
              },
            ),
            IconButton(
              icon: const Icon(Icons.videocam, color: Colors.purpleAccent),
              onPressed: () {
                ref.read(callStateProvider.notifier).startCall(
                  conversationId: conv.conversationId,
                  otherUsername: conv.otherUsername,
                  otherDeviceId: conv.otherDeviceId,
                  isVideo: true,
                );
              },
            ),
          ],
          if (conv.isGroup)
            IconButton(
              icon: const Icon(Icons.group),
              onPressed: () {
                Navigator.push(
                  context,
                  MaterialPageRoute(
                    builder: (context) => GroupDetailsPage(conversation: conv),
                  ),
                );
              },
            ),
        ],
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
                      final isMe = msg.senderDeviceId == myDeviceId;
                      final isSystem = msg.senderDeviceId == '00000000-0000-0000-0000-000000000000';
                      if (isSystem) {
                        return Center(
                          child: Container(
                            margin: const EdgeInsets.symmetric(vertical: 8),
                            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                            decoration: BoxDecoration(
                              color: Colors.white10,
                              borderRadius: BorderRadius.circular(8),
                            ),
                            child: Text(
                              msg.text,
                              style: const TextStyle(color: Colors.grey, fontSize: 12, fontStyle: FontStyle.italic),
                            ),
                          ),
                        );
                      }
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
                              _buildMessageContent(msg, conv, sessionToken),
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
          if (_uploadStatusText != null)
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
              color: const Color(0xFF1E1E2E),
              child: Row(
                children: [
                  const SizedBox(
                    width: 16,
                    height: 16,
                    child: CircularProgressIndicator(strokeWidth: 2, color: Colors.purpleAccent),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Text(
                      _uploadStatusText!,
                      style: const TextStyle(fontSize: 12, color: Colors.white70),
                    ),
                  ),
                  if (_uploadProgress != null)
                    Text(
                      '${(_uploadProgress! * 100).toInt()}%',
                      style: const TextStyle(fontSize: 12, color: Colors.purpleAccent, fontWeight: FontWeight.bold),
                    ),
                ],
              ),
            ),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 8),
            color: const Color(0xFF1E1E2E),
            child: Row(
              children: [
                if (!_isRecording) ...[
                  IconButton(
                    icon: const Icon(Icons.sentiment_satisfied_alt, color: Colors.purpleAccent),
                    onPressed: () {
                      final cursorPosition = _messageController.selection.baseOffset;
                      const emoji = "😊";
                      if (cursorPosition >= 0) {
                        final text = _messageController.text;
                        final newText = text.replaceRange(cursorPosition, cursorPosition, emoji);
                        _messageController.text = newText;
                        _messageController.selection = TextSelection.fromPosition(
                          TextPosition(offset: cursorPosition + emoji.length),
                        );
                      } else {
                        _messageController.text += emoji;
                      }
                      setState(() {});
                    },
                  ),
                  IconButton(
                    icon: const Icon(Icons.attach_file, color: Colors.purpleAccent),
                    onPressed: _showAttachmentMenu,
                  ),
                  IconButton(
                    icon: const Icon(Icons.camera_alt, color: Colors.purpleAccent),
                    onPressed: () => _pickAndSendImage(ImageSource.camera),
                  ),
                ],
                
                if (_isRecording)
                  Expanded(
                    child: Container(
                      height: 50,
                      padding: const EdgeInsets.symmetric(horizontal: 12),
                      decoration: BoxDecoration(
                        color: Colors.black26,
                        borderRadius: BorderRadius.circular(24),
                        border: Border.all(color: Colors.white10),
                      ),
                      child: Row(
                        children: [
                          TweenAnimationBuilder<double>(
                            tween: Tween(begin: 0.2, end: 1.0),
                            duration: const Duration(milliseconds: 600),
                            builder: (context, opacity, child) {
                              return Opacity(
                                opacity: _isRecordPaused ? 0.5 : opacity,
                                child: const Icon(Icons.fiber_manual_record, color: Colors.red, size: 16),
                              );
                            },
                          ),
                          const SizedBox(width: 8),
                          Text(
                            '0:${_recordDuration.toString().padLeft(2, '0')}',
                            style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 13, fontFamily: 'monospace'),
                          ),
                          const SizedBox(width: 12),
                          Expanded(
                            child: SizedBox(
                              height: 30,
                              child: CustomPaint(
                                painter: VoiceWaveformPainter(
                                  amplitudeHistory: _amplitudeHistory,
                                  color: Colors.purpleAccent,
                                ),
                              ),
                            ),
                          ),
                          if (!_isRecordLocked) ...[
                            const SizedBox(width: 4),
                            const Text(
                              '◀ Swipe left to cancel',
                              style: TextStyle(fontSize: 9, color: Colors.white54),
                            ),
                          ] else ...[
                            IconButton(
                              icon: Icon(_isRecordPaused ? Icons.play_arrow : Icons.pause, color: Colors.amberAccent, size: 18),
                              onPressed: () {
                                if (_isRecordPaused) {
                                  _resumeRecording();
                                } else {
                                  _pauseRecording();
                                }
                              },
                            ),
                            IconButton(
                              icon: const Icon(Icons.delete, color: Colors.redAccent, size: 18),
                              onPressed: _cancelRecording,
                            ),
                          ],
                        ],
                      ),
                    ),
                  )
                else
                  Expanded(
                    child: Container(
                      decoration: BoxDecoration(
                        color: const Color(0xFF0F0F15),
                        borderRadius: BorderRadius.circular(24),
                        border: Border.all(color: Colors.white10),
                      ),
                      child: TextField(
                        controller: _messageController,
                        onChanged: (text) {
                          setState(() {});
                        },
                        decoration: const InputDecoration(
                          hintText: 'Type a secure message...',
                          border: InputBorder.none,
                          contentPadding: EdgeInsets.symmetric(horizontal: 16, vertical: 10),
                        ),
                      ),
                    ),
                  ),

                const SizedBox(width: 6),

                if (_messageController.text.trim().isNotEmpty || (_isRecording && _isRecordLocked))
                  GestureDetector(
                    onTap: () {
                      if (_isRecording) {
                        _stopAndSendRecording();
                      } else {
                        _sendMessage();
                      }
                    },
                    child: const CircleAvatar(
                      backgroundColor: Colors.deepPurpleAccent,
                      radius: 22,
                      child: Icon(Icons.send, color: Colors.white, size: 18),
                    ),
                  )
                else
                  GestureDetector(
                    onVerticalDragUpdate: (details) {
                      if (_isRecording && !_isRecordLocked) {
                        if (details.localPosition.dy < -60) {
                          setState(() {
                            _isRecordLocked = true;
                          });
                        }
                      }
                    },
                    onHorizontalDragUpdate: (details) {
                      if (_isRecording && !_isRecordLocked) {
                        if (details.localPosition.dx < -60) {
                          _cancelRecording();
                        }
                      }
                    },
                    onLongPressStart: (_) => _startRecording(),
                    onLongPressEnd: (_) {
                      if (!_isRecordLocked) {
                        _stopAndSendRecording();
                      }
                    },
                    child: CircleAvatar(
                      backgroundColor: _isRecording ? Colors.red : const Color(0xFF8A5CFF).withOpacity(0.15),
                      radius: 22,
                      child: Icon(
                        _isRecording ? Icons.mic : Icons.mic_none,
                        color: _isRecording ? Colors.white : Colors.purpleAccent,
                        size: 20,
                      ),
                    ),
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
  
  // Media fields
  final String? type; // 'text', 'image', 'file', 'voice'
  final String? blobId;
  final String? fileKey;
  final String? filename;
  final String? mimeType;
  final int? fileSize;
  final int? durationSeconds;

  // Local decrypted cache of media file bytes
  final Uint8List? decryptedData;
  final bool isDownloading;

  ChatMessage({
    required this.messageId,
    required this.senderDeviceId,
    required this.text,
    required this.timestamp,
    this.type = 'text',
    this.blobId,
    this.fileKey,
    this.filename,
    this.mimeType,
    this.fileSize,
    this.durationSeconds,
    this.decryptedData,
    this.isDownloading = false,
  });

  ChatMessage copyWith({
    String? messageId,
    String? senderDeviceId,
    String? text,
    DateTime? timestamp,
    String? type,
    String? blobId,
    String? fileKey,
    String? filename,
    String? mimeType,
    int? fileSize,
    int? durationSeconds,
    Uint8List? decryptedData,
    bool? isDownloading,
  }) {
    return ChatMessage(
      messageId: messageId ?? this.messageId,
      senderDeviceId: senderDeviceId ?? this.senderDeviceId,
      text: text ?? this.text,
      timestamp: timestamp ?? this.timestamp,
      type: type ?? this.type,
      blobId: blobId ?? this.blobId,
      fileKey: fileKey ?? this.fileKey,
      filename: filename ?? this.filename,
      mimeType: mimeType ?? this.mimeType,
      fileSize: fileSize ?? this.fileSize,
      durationSeconds: durationSeconds ?? this.durationSeconds,
      decryptedData: decryptedData ?? this.decryptedData,
      isDownloading: isDownloading ?? this.isDownloading,
    );
  }
}

class ChatConversation {
  final String conversationId;
  final String otherUsername;
  final String otherAccountId;
  final String otherDeviceId;
  final List<ChatMessage> messages;
  final bool isGroup;
  final List<String> groupMemberUsernames;
  final List<String> groupMemberDeviceIds;

  ChatConversation({
    required this.conversationId,
    required this.otherUsername,
    required this.otherAccountId,
    required this.otherDeviceId,
    required this.messages,
    this.isGroup = false,
    this.groupMemberUsernames = const [],
    this.groupMemberDeviceIds = const [],
  });

  ChatConversation copyWith({
    List<ChatMessage>? messages,
    List<String>? groupMemberUsernames,
    List<String>? groupMemberDeviceIds,
  }) {
    return ChatConversation(
      conversationId: conversationId,
      otherUsername: otherUsername,
      otherAccountId: otherAccountId,
      otherDeviceId: otherDeviceId,
      messages: messages ?? this.messages,
      isGroup: isGroup,
      groupMemberUsernames: groupMemberUsernames ?? this.groupMemberUsernames,
      groupMemberDeviceIds: groupMemberDeviceIds ?? this.groupMemberDeviceIds,
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
  final Ref ref;
  VeilWebSocketClient? _wsClient;
  String? _myDeviceId;

  VeilWebSocketClient? get wsClient => _wsClient;
  String? get myDeviceId => _myDeviceId;
  
  ChatNotifier({required AuthApiClient api, required this.ref})
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

    // Register push token immediately (mock gateway)
    _api.registerPushToken(accessToken, 'mock-fcm-token-$myDeviceId').catchError((e) {
      debugPrint('[ChatNotifier] Register push token failed: $e');
    });

    // Load groups
    loadGroups(accessToken);
  }

  Future<void> loadGroups(String accessToken) async {
    try {
      final res = await _api.getGroups(accessToken);
      final List<dynamic> groupList = res['groups'] ?? [];
      final List<ChatConversation> loadedGroups = [];
      for (final g in groupList) {
        final id = g['id'] as String;
        final name = g['name'] as String;
        final members = g['members'] as List<dynamic>;
        final List<String> memberNames = [];
        final List<String> memberDevices = [];
        
        for (final m in members) {
          final username = m['username'] as String;
          memberNames.add(username);
          
          try {
            final userRes = await _api.lookupUser(username);
            final devices = userRes['devices'] as List<dynamic>;
            for (final d in devices) {
              memberDevices.add(d['device_id'] as String);
            }
          } catch (_) {}
        }
        
        loadedGroups.add(ChatConversation(
          conversationId: id,
          otherUsername: name,
          otherAccountId: 'Group Chat',
          otherDeviceId: '',
          messages: [],
          isGroup: true,
          groupMemberUsernames: memberNames,
          groupMemberDeviceIds: memberDevices,
        ));
      }
      
      final updated = List<ChatConversation>.from(state.conversations);
      for (final g in loadedGroups) {
        final existingIdx = updated.indexWhere((c) => c.conversationId == g.conversationId);
        if (existingIdx != -1) {
          final oldConv = updated[existingIdx];
          updated[existingIdx] = g.copyWith(messages: oldConv.messages);
        } else {
          updated.add(g);
        }
      }
      state = state.copyWith(conversations: updated);
    } catch (e) {
      debugPrint('[ChatNotifier] Failed to load groups: $e');
    }
  }

  Future<void> createGroupChat(String accessToken, String name) async {
    try {
      final result = await _api.createGroup(accessToken, name);
      final newGroupId = result['id'] as String;
      debugPrint('[ChatNotifier] Group created: $newGroupId');
      await loadGroups(accessToken);
    } catch (e) {
      debugPrint('[ChatNotifier] Group creation failed: $e');
      state = state.copyWith(error: e.toString());
      rethrow;
    }
  }

  Future<void> inviteToGroup(String accessToken, String groupId, String username) async {
    try {
      await _api.inviteMember(accessToken, groupId, username);
      debugPrint('[ChatNotifier] Invited user $username to group $groupId');
      await loadGroups(accessToken);
    } catch (e) {
      debugPrint('[ChatNotifier] Invite to group failed: $e');
      state = state.copyWith(error: e.toString());
      rethrow;
    }
  }

  Future<void> removeFromGroup(String accessToken, String groupId, String userId) async {
    try {
      await _api.removeMember(accessToken, groupId, userId);
      debugPrint('[ChatNotifier] Removed user $userId from group $groupId');
      await loadGroups(accessToken);
    } catch (e) {
      debugPrint('[ChatNotifier] Remove member failed: $e');
      state = state.copyWith(error: e.toString());
      rethrow;
    }
  }

  void _handleCallSignal(int signalType, String sdpOrCandidate, String senderDeviceId, String recipientDeviceId, String messageId) {
    final callNotifier = ref.read(callStateProvider.notifier);
    if (signalType == 8) {
      final isVideo = sdpOrCandidate.contains('m=video');
      callNotifier.receiveOffer(
        otherDeviceId: senderDeviceId,
        sdp: sdpOrCandidate,
        isVideo: isVideo,
      );
    } else {
      callNotifier.handleIncomingSignal(signalType, sdpOrCandidate);
    }
  }

  void _handleIncomingEnvelope(Uint8List binBytes) {
    try {
      final decoded = cbor.decode(binBytes);
      if (decoded is CborMap) {
        if (decoded.containsKey(CborString('signal_type'))) {
          final signalTypeVal = decoded[CborString('signal_type')];
          final signalType = (signalTypeVal is CborInt) ? signalTypeVal.toInt() : (signalTypeVal as CborSmallInt).value;
          final sdpOrCandidate = (decoded[CborString('sdp_or_candidate')] as CborString).toString();
          
          final senderDeviceBytes = (decoded[CborString('sender_device_id')] as CborBytes).bytes;
          final senderDeviceId = Uuid.unparse(senderDeviceBytes);

          final recipientDeviceBytes = (decoded[CborString('recipient_device_id')] as CborBytes).bytes;
          final recipientDeviceId = Uuid.unparse(recipientDeviceBytes);
          
          final messageIdBytes = (decoded[CborString('message_id')] as CborBytes).bytes;
          final messageId = Uuid.unparse(messageIdBytes);

          debugPrint('[ChatNotifier] Received Call Signal: type=$signalType sender=$senderDeviceId');
          _handleCallSignal(signalType, sdpOrCandidate, senderDeviceId, recipientDeviceId, messageId);
          return;
        }

        final msgIdBytes = (decoded[CborString('message_id')] as CborBytes).bytes;
        final convIdBytes = (decoded[CborString('conversation_id')] as CborBytes).bytes;
        final senderDeviceBytes = (decoded[CborString('sender_device_id')] as CborBytes).bytes;
        final ciphertextBytes = (decoded[CborString('ciphertext')] as CborBytes).bytes;

        final messageId = Uuid.unparse(msgIdBytes);
        final conversationId = Uuid.unparse(convIdBytes);
        final senderDeviceId = Uuid.unparse(senderDeviceBytes);
        final text = utf8.decode(ciphertextBytes);

        debugPrint('[ChatNotifier] Received message envelope over WS: "$text" in conv $conversationId');

        String displayText = text;
        String? msgType = 'text';
        String? blobId;
        String? fileKey;
        String? filename;
        String? mimeType;
        int? fileSize;
        int? durationSeconds;

        try {
          final payload = jsonDecode(text);
          if (payload is Map<String, dynamic> && payload.containsKey('type')) {
            msgType = payload['type'] as String?;
            blobId = payload['blob_id'] as String?;
            fileKey = payload['file_key'] as String?;
            filename = payload['filename'] as String?;
            mimeType = payload['mime_type'] as String?;
            fileSize = payload['file_size'] as int?;
            durationSeconds = payload['duration_seconds'] as int?;
            
            if (msgType == 'image') {
              displayText = 'Sent an image: ${filename ?? 'image.png'}';
            } else if (msgType == 'file') {
              displayText = 'Sent a file: ${filename ?? 'file.dat'}';
            } else if (msgType == 'voice') {
              displayText = 'Sent a voice message (${durationSeconds ?? 0}s)';
            }
          }
        } catch (_) {
          // Standard text message
        }

        final newMessage = ChatMessage(
          messageId: messageId,
          senderDeviceId: senderDeviceId,
          text: displayText,
          timestamp: DateTime.now(),
          type: msgType,
          blobId: blobId,
          fileKey: fileKey,
          filename: filename,
          mimeType: mimeType,
          fileSize: fileSize,
          durationSeconds: durationSeconds,
        );

        final index = state.conversations.indexWhere((c) => c.conversationId == conversationId);
        if (index != -1) {
          final conv = state.conversations[index];
          final updatedMessages = List<ChatMessage>.from(conv.messages)..add(newMessage);
          final updatedConversations = List<ChatConversation>.from(state.conversations);
          updatedConversations[index] = conv.copyWith(messages: updatedMessages);
          state = state.copyWith(conversations: updatedConversations);
        } else {
          final newConv = ChatConversation(
            conversationId: conversationId,
            otherUsername: senderDeviceId == '00000000-0000-0000-0000-000000000000'
                ? 'System Alert'
                : 'Device: ' + senderDeviceId.substring(0, 8),
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

      final firstDevice = devices.first as Map<String, dynamic>;
      final otherDeviceId = firstDevice['device_id'] as String;

      final conversationId = const Uuid().v4();

      final newConv = ChatConversation(
        conversationId: conversationId,
        otherUsername: otherUsername,
        otherAccountId: otherAccountId,
        otherDeviceId: otherDeviceId,
        messages: [],
      );

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

    if (conv.isGroup) {
      for (final deviceId in conv.groupMemberDeviceIds) {
        if (deviceId == _myDeviceId) continue;
        
        final msgIdBytes = Uuid.parse(messageId);
        final convIdBytes = Uuid.parse(conversationId);
        final senderDeviceBytes = Uuid.parse(_myDeviceId!);
        final recipientDeviceBytes = Uuid.parse(deviceId);
        final ciphertextBytes = Uint8List.fromList(utf8.encode(text));

        final map = {
          'message_id': CborBytes(msgIdBytes),
          'conversation_id': CborBytes(convIdBytes),
          'sender_device_id': CborBytes(senderDeviceBytes),
          'recipient_device_id': CborBytes(recipientDeviceBytes),
          'timestamp': DateTime.now().millisecondsSinceEpoch,
          'dh_pub': CborBytes(Uint8List(32)),
          'ciphertext': CborBytes(ciphertextBytes),
          'signature': CborBytes(Uint8List(64)),
          'major_version': 1,
          'minor_version': 0,
          'message_number': conv.messages.length + 1,
        };

        final binBytes = cbor.encode(CborValue(map));
        _wsClient!.sendEnvelope(Uint8List.fromList(binBytes));
      }
    } else {
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
        'dh_pub': CborBytes(Uint8List(32)),
        'ciphertext': CborBytes(ciphertextBytes),
        'signature': CborBytes(Uint8List(64)),
        'major_version': 1,
        'minor_version': 0,
        'message_number': conv.messages.length + 1,
      };

      final binBytes = cbor.encode(CborValue(map));
      _wsClient!.sendEnvelope(Uint8List.fromList(binBytes));
    }

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

  Future<void> sendMediaMessage({
    required String sessionToken,
    required String conversationId,
    required String type, // 'image', 'file', 'voice'
    required String filename,
    required String mimeType,
    required Uint8List fileBytes,
    int? durationSeconds,
    Function(double progress)? onProgress,
  }) async {
    debugPrint('[AttachmentPipeline] file selected: filename=$filename type=$type size=${fileBytes.length}');

    if (_wsClient == null || !state.isConnected) {
      throw Exception('Not connected to chat network');
    }

    final index = state.conversations.indexWhere((c) => c.conversationId == conversationId);
    if (index == -1) throw Exception('Conversation not found');
    final conv = state.conversations[index];

    final mockKey = List.generate(32, (i) => i).join(''); // simple mock string representation

    // Real SHA-256 hash generation of file bytes
    final hashObj = await Sha256().hash(fileBytes);
    final fileHash = hashObj.bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join('');
    debugPrint('[AttachmentPipeline] hash generated: $fileHash');

    final int totalSize = fileBytes.length;
    
    // Use 4 MiB chunks as required by the backend uploader protocol
    final int chunkSize = 4 * 1024 * 1024;
    final int chunkCount = totalSize == 0 ? 1 : (totalSize / chunkSize).ceil();

    final messageId = const Uuid().v4();
    debugPrint('[AttachmentPipeline] generated message_id: $messageId');

    onProgress?.call(0.1);
    debugPrint('[AttachmentPipeline] upload initiated: conversationId=$conversationId fileSize=$totalSize chunkCount=$chunkCount');
    final blobId = await _api.initiateUpload(
      sessionToken: sessionToken,
      conversationId: conversationId,
      fileSize: totalSize,
      fileHash: fileHash,
      mimeType: mimeType,
      chunkCount: chunkCount,
    );
    debugPrint('[AttachmentPipeline] upload transaction: blob_id=$blobId, size=$totalSize');
    debugPrint('[AttachmentPipeline] upload response received: blobId=$blobId');

    for (int i = 0; i < chunkCount; i++) {
      final start = i * chunkSize;
      final end = (start + chunkSize > totalSize) ? totalSize : start + chunkSize;
      final chunkData = fileBytes.sublist(start, end);

      debugPrint('[AttachmentPipeline] chunk uploading: index=$i/$chunkCount size=${chunkData.length}');
      await _api.uploadChunk(
        sessionToken: sessionToken,
        blobId: blobId,
        chunkIndex: i,
        chunkBytes: chunkData,
      );
      debugPrint('[AttachmentPipeline] chunk uploaded: index=$i/$chunkCount');

      final progress = 0.1 + (0.8 * (i + 1) / chunkCount);
      onProgress?.call(progress);
    }
    debugPrint('[AttachmentPipeline] upload finalized: blobId=$blobId');

    onProgress?.call(0.90);

    final payloadJson = jsonEncode({
      'type': type,
      'blob_id': blobId,
      'file_key': mockKey,
      'filename': filename,
      'mime_type': mimeType,
      'file_size': totalSize,
      if (durationSeconds != null) 'duration_seconds': durationSeconds,
    });

    final msgIdBytes = Uuid.parse(messageId);
    final convIdBytes = Uuid.parse(conversationId);
    final senderDeviceBytes = Uuid.parse(_myDeviceId!);
    
    final String recipientDeviceId = conv.isGroup ? '' : conv.otherDeviceId;

    if (conv.isGroup) {
      debugPrint('[AttachmentPipeline] group message dispatch starting: conversationId=$conversationId');
      for (final deviceId in conv.groupMemberDeviceIds) {
        if (deviceId == _myDeviceId) continue;

        final recipientDeviceBytes = Uuid.parse(deviceId);
        final ciphertextBytes = Uint8List.fromList(utf8.encode(payloadJson));

        final map = {
          'message_id': CborBytes(msgIdBytes),
          'conversation_id': CborBytes(convIdBytes),
          'sender_device_id': CborBytes(senderDeviceBytes),
          'recipient_device_id': CborBytes(recipientDeviceBytes),
          'timestamp': DateTime.now().millisecondsSinceEpoch,
          'dh_pub': CborBytes(Uint8List(32)),
          'ciphertext': CborBytes(ciphertextBytes),
          'signature': CborBytes(Uint8List(64)),
          'major_version': 1,
          'minor_version': 0,
          'message_number': conv.messages.length + 1,
        };

        final binBytes = cbor.encode(CborValue(map));
        _wsClient!.sendEnvelope(Uint8List.fromList(binBytes));
      }
    } else {
      debugPrint('[AttachmentPipeline] 1-to-1 message dispatch starting: messageId=$messageId recipient=$recipientDeviceId');
      final recipientDeviceBytes = Uuid.parse(recipientDeviceId);
      final ciphertextBytes = Uint8List.fromList(utf8.encode(payloadJson));

      final map = {
        'message_id': CborBytes(msgIdBytes),
        'conversation_id': CborBytes(convIdBytes),
        'sender_device_id': CborBytes(senderDeviceBytes),
        'recipient_device_id': CborBytes(recipientDeviceBytes),
        'timestamp': DateTime.now().millisecondsSinceEpoch,
        'dh_pub': CborBytes(Uint8List(32)),
        'ciphertext': CborBytes(ciphertextBytes),
        'signature': CborBytes(Uint8List(64)),
        'major_version': 1,
        'minor_version': 0,
        'message_number': conv.messages.length + 1,
      };

      final binBytes = cbor.encode(CborValue(map));
      _wsClient!.sendEnvelope(Uint8List.fromList(binBytes));
    }

    // Wait a brief period (e.g. 200ms) to allow the server's asynchronous task to queue
    // the messages in `pending_messages` before we bind the attachment.
    await Future.delayed(const Duration(milliseconds: 200));

    debugPrint('[AttachmentPipeline] attachment message_id: $messageId');
    debugPrint('[AttachmentPipeline] attachment bind step: blob_id=$blobId, message_id=$messageId');
    debugPrint('[AttachmentPipeline] attachment binding starting: blobId=$blobId messageId=$messageId');
    try {
      await _api.bindAttachment(
        sessionToken: sessionToken,
        blobId: blobId,
        messageId: messageId,
      );
      debugPrint('[AttachmentPipeline] attachment bound: blobId=$blobId');
    } catch (e) {
      debugPrint('[AttachmentPipeline] bindAttachment warning/info: $e');
    }
    onProgress?.call(0.95);

    final localMessage = ChatMessage(
      messageId: messageId,
      senderDeviceId: _myDeviceId!,
      text: type == 'image'
          ? 'Sent an image: $filename'
          : type == 'file'
              ? 'Sent a file: $filename'
              : 'Sent a voice message (${durationSeconds}s)',
      timestamp: DateTime.now(),
      type: type,
      blobId: blobId,
      fileKey: mockKey,
      filename: filename,
      mimeType: mimeType,
      fileSize: totalSize,
      durationSeconds: durationSeconds,
      decryptedData: fileBytes,
    );

    final updatedMessages = List<ChatMessage>.from(conv.messages)..add(localMessage);
    final updatedConversations = List<ChatConversation>.from(state.conversations);
    updatedConversations[index] = conv.copyWith(messages: updatedMessages);
    state = state.copyWith(conversations: updatedConversations);
    onProgress?.call(1.0);
    debugPrint('[AttachmentPipeline] inserted message_id: $messageId');
    debugPrint('[AttachmentPipeline] message sent: messageId=$messageId');
  }

  Future<void> downloadMedia({
    required String sessionToken,
    required String conversationId,
    required String messageId,
    required String blobId,
  }) async {
    final index = state.conversations.indexWhere((c) => c.conversationId == conversationId);
    if (index == -1) return;
    final conv = state.conversations[index];

    final msgIndex = conv.messages.indexWhere((m) => m.messageId == messageId);
    if (msgIndex == -1) return;
    
    final updatedConversations = List<ChatConversation>.from(state.conversations);
    final updatedMessages = List<ChatMessage>.from(conv.messages);
    updatedMessages[msgIndex] = updatedMessages[msgIndex].copyWith(isDownloading: true);
    updatedConversations[index] = conv.copyWith(messages: updatedMessages);
    state = state.copyWith(conversations: updatedConversations);

    try {

      final dataBytes = await _api.downloadAttachment(
        sessionToken: sessionToken,
        blobId: blobId,
      );

      final freshConversations = List<ChatConversation>.from(state.conversations);
      final freshMessages = List<ChatMessage>.from(freshConversations[index].messages);
      freshMessages[msgIndex] = freshMessages[msgIndex].copyWith(
        isDownloading: false,
        decryptedData: Uint8List.fromList(dataBytes),
      );
      freshConversations[index] = freshConversations[index].copyWith(messages: freshMessages);
      state = state.copyWith(conversations: freshConversations);
      
      debugPrint('[ChatNotifier] Attachment downloaded: $blobId');
    } catch (e) {
      debugPrint('[ChatNotifier] Download attachment failed: $e');
      
      final freshConversations = List<ChatConversation>.from(state.conversations);
      final freshMessages = List<ChatMessage>.from(freshConversations[index].messages);
      freshMessages[msgIndex] = freshMessages[msgIndex].copyWith(isDownloading: false);
      freshConversations[index] = freshConversations[index].copyWith(messages: freshMessages);
      state = state.copyWith(conversations: freshConversations);
      rethrow;
    }
  }
}

final chatProvider = StateNotifierProvider<ChatNotifier, ChatState>((ref) {
  final api = ref.watch(authApiClientProvider);
  return ChatNotifier(api: api, ref: ref);
});

void _showNewGroupDialog(BuildContext context, WidgetRef ref) {
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
            title: const Text('Create New Group Chat'),
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
                    hintText: 'Type group name...',
                    labelText: 'Group Name',
                    prefixIcon: Icon(Icons.group),
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
                  final name = controller.text.trim();
                  if (name.isEmpty) return;
                  
                  setState(() {
                    loading = true;
                    error = null;
                  });

                  try {
                    final authState = ref.read(authProvider);
                    if (authState is AuthSuccess) {
                      await ref.read(chatProvider.notifier).createGroupChat(authState.session.accessToken, name);
                      if (context.mounted) {
                        Navigator.pop(context);
                      }
                    } else {
                      throw Exception('Not authenticated.');
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

class GroupDetailsPage extends ConsumerStatefulWidget {
  final ChatConversation conversation;

  const GroupDetailsPage({super.key, required this.conversation});

  @override
  ConsumerState<GroupDetailsPage> createState() => _GroupDetailsPageState();
}

class _GroupDetailsPageState extends ConsumerState<GroupDetailsPage> {
  final _inviteController = TextEditingController();
  bool _loading = false;
  String? _error;

  @override
  Widget build(BuildContext context) {
    final authState = ref.watch(authProvider);
    final chatState = ref.watch(chatProvider);
    
    final conv = chatState.conversations.firstWhere(
      (c) => c.conversationId == widget.conversation.conversationId,
      orElse: () => widget.conversation,
    );

    String myUserId = '';
    String sessionToken = '';
    if (authState is AuthSuccess) {
      myUserId = authState.credentials.userId;
      sessionToken = authState.session.accessToken;
    }

    return Scaffold(
      appBar: AppBar(
        title: Text('${conv.otherUsername} Details'),
        backgroundColor: const Color(0xFF1E1E2E),
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(24),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            if (_error != null) ...[
              Text(_error!, style: const TextStyle(color: Colors.redAccent)),
              const SizedBox(height: 12),
            ],
            const Text(
              'Invite Member',
              style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold, color: Colors.white),
            ),
            const SizedBox(height: 12),
            Row(
              children: [
                Expanded(
                  child: TextField(
                    controller: _inviteController,
                    decoration: const InputDecoration(
                      hintText: 'Username or Account ID...',
                    ),
                  ),
                ),
                const SizedBox(width: 12),
                ElevatedButton(
                  style: ElevatedButton.styleFrom(backgroundColor: Colors.deepPurpleAccent),
                  onPressed: _loading ? null : () async {
                    final query = _inviteController.text.trim();
                    if (query.isEmpty) return;
                    setState(() {
                      _loading = true;
                      _error = null;
                    });
                    try {
                      await ref.read(chatProvider.notifier).inviteToGroup(sessionToken, conv.conversationId, query);
                      _inviteController.clear();
                      setState(() {
                        _loading = false;
                      });
                      ScaffoldMessenger.of(context).showSnackBar(
                        const SnackBar(content: Text('Member invited successfully!')),
                      );
                    } catch (e) {
                      setState(() {
                        _loading = false;
                        _error = e.toString().replaceAll('Exception: ', '');
                      });
                    }
                  },
                  child: const Text('Invite'),
                ),
              ],
            ),
            const SizedBox(height: 32),
            const Text(
              'Group Members',
              style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold, color: Colors.white),
            ),
            const SizedBox(height: 12),
            ListView.builder(
              shrinkWrap: true,
              physics: const NeverScrollableScrollPhysics(),
              itemCount: conv.groupMemberUsernames.length,
              itemBuilder: (context, index) {
                final username = conv.groupMemberUsernames[index];
                return ListTile(
                  leading: CircleAvatar(
                    backgroundColor: Colors.deepPurpleAccent.withOpacity(0.2),
                    child: Text(
                      username.isNotEmpty ? username.substring(0, 1).toUpperCase() : 'U',
                      style: const TextStyle(color: Colors.purpleAccent),
                    ),
                  ),
                  title: Text(username, style: const TextStyle(color: Colors.white)),
                  trailing: IconButton(
                    icon: const Icon(Icons.remove_circle, color: Colors.redAccent),
                    onPressed: () async {
                      try {
                        final userRes = await ref.read(chatProvider.notifier)._api.lookupUser(username);
                        final targetUserId = userRes['user_id'] as String;
                        setState(() {
                          _loading = true;
                          _error = null;
                        });
                        await ref.read(chatProvider.notifier).removeFromGroup(sessionToken, conv.conversationId, targetUserId);
                        setState(() {
                          _loading = false;
                        });
                        ScaffoldMessenger.of(context).showSnackBar(
                          const SnackBar(content: Text('Member removed successfully!')),
                        );
                      } catch (e) {
                        setState(() {
                          _loading = false;
                          _error = e.toString().replaceAll('Exception: ', '');
                        });
                      }
                    },
                  ),
                );
              },
            ),
            const SizedBox(height: 32),
            ElevatedButton(
              style: ElevatedButton.styleFrom(backgroundColor: Colors.redAccent),
              onPressed: () async {
                try {
                  setState(() {
                    _loading = true;
                    _error = null;
                  });
                  await ref.read(chatProvider.notifier).removeFromGroup(sessionToken, conv.conversationId, myUserId);
                  if (context.mounted) {
                    Navigator.pop(context); // Pop details page
                    Navigator.pop(context); // Pop chat room page
                  }
                } catch (e) {
                  setState(() {
                    _loading = false;
                    _error = e.toString().replaceAll('Exception: ', '');
                  });
                }
              },
              child: const Text('Leave Group'),
            ),
          ],
        ),
      ),
    );
  }
}

// ==========================================
// VoIP / Video WebRTC Calling Infrastructure
// ==========================================

enum CallStatus {
  idle,
  ringing, // Incoming call ringing
  calling, // Outgoing call calling
  connected,
}

class CallStateModel {
  final CallStatus status;
  final String conversationId;
  final String otherUsername;
  final String otherDeviceId;
  final bool isVideo;
  final bool isMuted;
  final bool isCameraOff;
  final bool isSpeakerphone;
  final int duration;
  final MediaStream? localStream;
  final MediaStream? remoteStream;

  CallStateModel({
    this.status = CallStatus.idle,
    this.conversationId = '',
    this.otherUsername = '',
    this.otherDeviceId = '',
    this.isVideo = false,
    this.isMuted = false,
    this.isCameraOff = false,
    this.isSpeakerphone = false,
    this.duration = 0,
    this.localStream,
    this.remoteStream,
  });

  CallStateModel copyWith({
    CallStatus? status,
    String? conversationId,
    String? otherUsername,
    String? otherDeviceId,
    bool? isVideo,
    bool? isMuted,
    bool? isCameraOff,
    bool? isSpeakerphone,
    int? duration,
    MediaStream? localStream,
    MediaStream? remoteStream,
  }) {
    return CallStateModel(
      status: status ?? this.status,
      conversationId: conversationId ?? this.conversationId,
      otherUsername: otherUsername ?? this.otherUsername,
      otherDeviceId: otherDeviceId ?? this.otherDeviceId,
      isVideo: isVideo ?? this.isVideo,
      isMuted: isMuted ?? this.isMuted,
      isCameraOff: isCameraOff ?? this.isCameraOff,
      isSpeakerphone: isSpeakerphone ?? this.isSpeakerphone,
      duration: duration ?? this.duration,
      localStream: localStream ?? this.localStream,
      remoteStream: remoteStream ?? this.remoteStream,
    );
  }
}

class CallStateNotifier extends StateNotifier<CallStateModel> {
  final Ref _ref;
  RTCPeerConnection? _peerConnection;
  Timer? _durationTimer;
  final RTCVideoRenderer localRenderer = RTCVideoRenderer();
  final RTCVideoRenderer remoteRenderer = RTCVideoRenderer();
  String? _incomingSdp;
  MediaStream? _localStream;

  CallStateNotifier(this._ref) : super(CallStateModel()) {
    _initRenderers();
  }

  Future<void> _initRenderers() async {
    await localRenderer.initialize();
    await remoteRenderer.initialize();
  }

  @override
  void dispose() {
    _durationTimer?.cancel();
    localRenderer.dispose();
    remoteRenderer.dispose();
    super.dispose();
  }

  void _sendSignaling(int signalType, String sdpOrCandidate) {
    final chatState = _ref.read(chatProvider.notifier);
    final wsClient = chatState.wsClient;
    final myDeviceId = chatState.myDeviceId;
    
    if (wsClient == null || myDeviceId == null || state.otherDeviceId.isEmpty) return;

    final frame = {
      'message_id': CborBytes(Uuid.parse(const Uuid().v4())),
      'sender_device_id': CborBytes(Uuid.parse(myDeviceId)),
      'recipient_device_id': CborBytes(Uuid.parse(state.otherDeviceId)),
      'signal_type': signalType,
      'sdp_or_candidate': CborString(sdpOrCandidate),
      'timestamp': DateTime.now().millisecondsSinceEpoch,
    };

    final binBytes = cbor.encode(CborValue(frame));
    wsClient.sendEnvelope(Uint8List.fromList(binBytes));
  }

  Future<void> startCall({
    required String conversationId,
    required String otherUsername,
    required String otherDeviceId,
    required bool isVideo,
  }) async {
    debugPrint('[CallPipeline] call button pressed: isVideo=$isVideo otherUsername=$otherUsername otherDeviceId=$otherDeviceId');
    
    debugPrint('[CallPipeline] state transitions: status=calling');
    state = CallStateModel(
      status: CallStatus.calling,
      conversationId: conversationId,
      otherUsername: otherUsername,
      otherDeviceId: otherDeviceId,
      isVideo: isVideo,
    );

    try {
      debugPrint('[CallPipeline] requesting camera & mic permissions');
      await [Permission.camera, Permission.microphone].request();

      final Map<String, dynamic> mediaConstraints = {
        'audio': true,
        'video': isVideo ? {
          'facingMode': 'user',
          'width': '640',
          'height': '480',
        } : false,
      };

      debugPrint('[CallPipeline] getting user media');
      final MediaStream stream = await navigator.mediaDevices.getUserMedia(mediaConstraints);
      _localStream = stream;
      localRenderer.srcObject = stream;
      state = state.copyWith(localStream: stream);

      final Map<String, dynamic> configuration = {
        'iceServers': [
          {'urls': 'stun:stun.l.google.com:19302'},
        ]
      };
      
      debugPrint('[CallPipeline] creating RTCPeerConnection');
      _peerConnection = await createPeerConnection(configuration);

      stream.getTracks().forEach((track) {
        _peerConnection!.addTrack(track, stream);
      });

      _peerConnection!.onIceCandidate = (RTCIceCandidate candidate) {
        debugPrint('[CallPipeline] ICE candidate sent: ${candidate.candidate}');
        _sendSignaling(10, jsonEncode({
          'candidate': candidate.candidate,
          'sdpMid': candidate.sdpMid,
          'sdpMLineIndex': candidate.sdpMLineIndex,
        }));
      };

      _peerConnection!.onTrack = (RTCTrackEvent event) {
        if (event.streams.isNotEmpty) {
          debugPrint('[CallPipeline] remote stream track received');
          remoteRenderer.srcObject = event.streams[0];
          state = state.copyWith(remoteStream: event.streams[0]);
        }
      };

      debugPrint('[CallPipeline] creating WebRTC offer');
      final RTCSessionDescription offer = await _peerConnection!.createOffer();
      debugPrint('[CallPipeline] offer created');

      await _peerConnection!.setLocalDescription(offer);

      debugPrint('[CallPipeline] offer sent to websocket');
      _sendSignaling(8, offer.sdp ?? '');
      debugPrint('[CallStateNotifier] Outgoing WebRTC call started');
    } catch (e) {
      debugPrint('[CallStateNotifier] Error starting call: $e');
      hangup();
    }
  }

  Future<void> receiveOffer({
    required String otherDeviceId,
    required String sdp,
    required bool isVideo,
  }) async {
    debugPrint('[CallPipeline] offer received: isVideo=$isVideo sender=$otherDeviceId');
    debugPrint('[CallPipeline] state transitions: status=ringing');
    state = CallStateModel(
      status: CallStatus.ringing,
      conversationId: '',
      otherUsername: 'Device: ' + otherDeviceId.substring(0, 8),
      otherDeviceId: otherDeviceId,
      isVideo: isVideo,
    );
    _incomingSdp = sdp;
  }

  Future<void> acceptCall() async {
    if (_incomingSdp == null) return;
    debugPrint('[CallPipeline] accept call pressed');

    try {
      debugPrint('[CallPipeline] requesting camera & mic permissions');
      await [Permission.camera, Permission.microphone].request();

      final Map<String, dynamic> mediaConstraints = {
        'audio': true,
        'video': state.isVideo ? {
          'facingMode': 'user',
          'width': '640',
          'height': '480',
        } : false,
      };

      debugPrint('[CallPipeline] getting user media');
      final MediaStream stream = await navigator.mediaDevices.getUserMedia(mediaConstraints);
      _localStream = stream;
      localRenderer.srcObject = stream;
      state = state.copyWith(localStream: stream);

      final Map<String, dynamic> configuration = {
        'iceServers': [
          {'urls': 'stun:stun.l.google.com:19302'},
        ]
      };
      
      debugPrint('[CallPipeline] creating RTCPeerConnection');
      _peerConnection = await createPeerConnection(configuration);

      stream.getTracks().forEach((track) {
        _peerConnection!.addTrack(track, stream);
      });

      _peerConnection!.onIceCandidate = (RTCIceCandidate candidate) {
        debugPrint('[CallPipeline] ICE candidate sent: ${candidate.candidate}');
        _sendSignaling(10, jsonEncode({
          'candidate': candidate.candidate,
          'sdpMid': candidate.sdpMid,
          'sdpMLineIndex': candidate.sdpMLineIndex,
        }));
      };

      _peerConnection!.onTrack = (RTCTrackEvent event) {
        if (event.streams.isNotEmpty) {
          debugPrint('[CallPipeline] remote stream track received');
          remoteRenderer.srcObject = event.streams[0];
          state = state.copyWith(remoteStream: event.streams[0]);
        }
      };

      debugPrint('[CallPipeline] setting remote offer description');
      await _peerConnection!.setRemoteDescription(RTCSessionDescription(_incomingSdp!, 'offer'));

      debugPrint('[CallPipeline] creating WebRTC answer');
      final RTCSessionDescription answer = await _peerConnection!.createAnswer();
      await _peerConnection!.setLocalDescription(answer);

      debugPrint('[CallPipeline] answer sent to websocket');
      _sendSignaling(9, answer.sdp ?? '');
      _startTimer();
      
      debugPrint('[CallPipeline] state transitions: status=connected');
      state = state.copyWith(status: CallStatus.connected);
      debugPrint('[CallStateNotifier] WebRTC call accepted');
    } catch (e) {
      debugPrint('[CallStateNotifier] Error accepting call: $e');
      hangup();
    }
  }

  Future<void> handleIncomingSignal(int type, String sdpOrCandidate) async {
    if (type == 9 && _peerConnection != null) {
      debugPrint('[CallPipeline] answer received from websocket');
      await _peerConnection!.setRemoteDescription(RTCSessionDescription(sdpOrCandidate, 'answer'));
      _startTimer();
      debugPrint('[CallPipeline] state transitions: status=connected');
      state = state.copyWith(status: CallStatus.connected);
      debugPrint('[CallStateNotifier] WebRTC connected');
    } else if (type == 10 && _peerConnection != null) {
      try {
        final data = jsonDecode(sdpOrCandidate);
        debugPrint('[CallPipeline] ICE candidate received: ${data['candidate']}');
        final candidate = RTCIceCandidate(
          data['candidate'],
          data['sdpMid'],
          data['sdpMLineIndex'],
        );
        await _peerConnection!.addCandidate(candidate);
      } catch (e) {
        debugPrint('[CallStateNotifier] Error adding ICE candidate: $e');
      }
    } else if (type == 11) {
      debugPrint('[CallStateNotifier] Peer declined or disconnected call');
      hangup(sendDeclineFrame: false);
    }
  }

  Future<void> hangup({bool sendDeclineFrame = true}) async {
    debugPrint('[CallPipeline] hangup requested: sendDeclineFrame=$sendDeclineFrame');
    if (sendDeclineFrame && state.status != CallStatus.idle) {
      _sendSignaling(11, 'hangup');
    }

    _durationTimer?.cancel();
    _incomingSdp = null;

    try {
      if (_localStream != null) {
        for (var track in _localStream!.getTracks()) {
          track.stop();
        }
        await _localStream!.dispose();
      }
      await _peerConnection?.close();
    } catch (e) {
      debugPrint('[CallStateNotifier] Error disposing WebRTC resources: $e');
    }

    _localStream = null;
    _peerConnection = null;
    localRenderer.srcObject = null;
    remoteRenderer.srcObject = null;

    debugPrint('[CallPipeline] state transitions: status=idle');
    state = CallStateModel(status: CallStatus.idle);
    debugPrint('[CallStateNotifier] WebRTC calling resources cleaned up');
  }

  void _startTimer() {
    _durationTimer?.cancel();
    _durationTimer = Timer.periodic(const Duration(seconds: 1), (timer) {
      state = state.copyWith(duration: state.duration + 1);
    });
  }

  void toggleMute() {
    if (_localStream != null) {
      final audioTracks = _localStream!.getAudioTracks();
      for (final track in audioTracks) {
        track.enabled = !track.enabled;
      }
      state = state.copyWith(isMuted: !state.isMuted);
    }
  }

  void toggleCamera() {
    if (_localStream != null && state.isVideo) {
      final videoTracks = _localStream!.getVideoTracks();
      for (final track in videoTracks) {
        track.enabled = !track.enabled;
      }
      state = state.copyWith(isCameraOff: !state.isCameraOff);
    }
  }

  void toggleSpeakerphone() {
    if (_localStream != null) {
      Helper.setSpeakerphoneOn(!state.isSpeakerphone);
      state = state.copyWith(isSpeakerphone: !state.isSpeakerphone);
    }
  }

  void switchCamera() {
    if (_localStream != null && state.isVideo) {
      final videoTracks = _localStream!.getVideoTracks();
      if (videoTracks.isNotEmpty) {
        Helper.switchCamera(videoTracks.first);
      }
    }
  }
}

final callStateProvider = StateNotifierProvider<CallStateNotifier, CallStateModel>((ref) {
  return CallStateNotifier(ref);
});

class CallOverlayWrapper extends ConsumerWidget {
  const CallOverlayWrapper({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final callState = ref.watch(callStateProvider);
    if (callState.status == CallStatus.idle) {
      return const SizedBox.shrink();
    }
    return Positioned.fill(
      child: Material(
        color: Colors.transparent,
        child: CallScreen(callState: callState),
      ),
    );
  }
}

class CallScreen extends ConsumerWidget {
  final CallStateModel callState;
  const CallScreen({super.key, required this.callState});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final callNotifier = ref.read(callStateProvider.notifier);

    String durationText(int sec) {
      final m = (sec ~/ 60).toString().padLeft(2, '0');
      final s = (sec % 60).toString().padLeft(2, '0');
      return '$m:$s';
    }

    return Scaffold(
      backgroundColor: const Color(0xFF0B0814),
      body: Stack(
        children: [
          // 1. Video background (Connected video call)
          if (callState.status == CallStatus.connected && callState.isVideo && callState.remoteStream != null)
            Positioned.fill(
              child: RTCVideoView(
                callNotifier.remoteRenderer,
                objectFit: RTCVideoViewObjectFit.RTCVideoViewObjectFitCover,
              ),
            )
          else
            // Dark audio/waiting layout
            Positioned.fill(
              child: Container(
                decoration: const BoxDecoration(
                  gradient: LinearGradient(
                    colors: [Color(0xFF0B0814), Color(0xFF1F1035)],
                    begin: Alignment.topCenter,
                    end: Alignment.bottomCenter,
                  ),
                ),
                child: Column(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    // Pulse calling avatar
                    TweenAnimationBuilder<double>(
                      tween: Tween(begin: 1.0, end: 1.15),
                      duration: const Duration(seconds: 1),
                      curve: Curves.easeInOut,
                      onEnd: () {},
                      builder: (context, scale, child) {
                        return Transform.scale(
                          scale: callState.status == CallStatus.connected ? 1.0 : scale,
                          child: Container(
                            width: 120,
                            height: 120,
                            decoration: BoxDecoration(
                              shape: BoxShape.circle,
                              color: const Color(0xFF8A5CFF).withOpacity(0.2),
                              border: Border.all(color: const Color(0xFF8A5CFF), width: 3),
                            ),
                            child: const Icon(Icons.person, size: 70, color: Colors.white),
                          ),
                        );
                      },
                    ),
                    const SizedBox(height: 24),
                    Text(
                      callState.otherUsername,
                      style: const TextStyle(fontSize: 22, fontWeight: FontWeight.bold),
                    ),
                    const SizedBox(height: 8),
                    Text(
                      callState.status == CallStatus.calling
                          ? 'Calling...'
                          : callState.status == CallStatus.ringing
                              ? 'Incoming ${callState.isVideo ? 'Video' : 'Voice'} Call...'
                              : 'Connected',
                      style: const TextStyle(color: Colors.greenAccent, fontSize: 14),
                    ),
                  ],
                ),
              ),
            ),

          // 2. Local PIP Video preview in top corner
          if (callState.status == CallStatus.connected && callState.isVideo && callState.localStream != null && !callState.isCameraOff)
            Positioned(
              top: 40,
              right: 20,
              width: 110,
              height: 150,
              child: Container(
                decoration: BoxDecoration(
                  borderRadius: BorderRadius.circular(12),
                  border: Border.all(color: Colors.white30, width: 2),
                ),
                child: ClipRRect(
                  borderRadius: BorderRadius.circular(10),
                  child: RTCVideoView(
                    callNotifier.localRenderer,
                    mirror: true,
                    objectFit: RTCVideoViewObjectFit.RTCVideoViewObjectFitCover,
                  ),
                ),
              ),
            ),

          // 3. Status call timer HUD
          if (callState.status == CallStatus.connected)
            Positioned(
              top: 45,
              left: 20,
              child: Container(
                padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                decoration: BoxDecoration(
                  color: Colors.black54,
                  borderRadius: BorderRadius.circular(16),
                ),
                child: Row(
                  children: [
                    const Icon(Icons.timer, size: 14, color: Colors.greenAccent),
                    const SizedBox(width: 6),
                    Text(
                      durationText(callState.duration),
                      style: const TextStyle(fontSize: 13, fontWeight: FontWeight.bold),
                    ),
                  ],
                ),
              ),
            ),

          // 4. Action buttons overlay at bottom
          Positioned(
            bottom: 40,
            left: 20,
            right: 20,
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                if (callState.status == CallStatus.ringing)
                  // Incoming Accept/Reject Row
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                    children: [
                      FloatingActionButton(
                        heroTag: 'decline_call',
                        backgroundColor: Colors.red,
                        onPressed: () => callNotifier.hangup(),
                        child: const Icon(Icons.call_end, color: Colors.white),
                      ),
                      FloatingActionButton(
                        heroTag: 'accept_call',
                        backgroundColor: Colors.green,
                        onPressed: () => callNotifier.acceptCall(),
                        child: const Icon(Icons.call, color: Colors.white),
                      ),
                    ],
                  )
                else
                  // Outgoing/Connected Controller Bar
                  Container(
                    padding: const EdgeInsets.symmetric(vertical: 14, horizontal: 16),
                    decoration: BoxDecoration(
                      color: Colors.black87,
                      borderRadius: BorderRadius.circular(24),
                      border: Border.all(color: Colors.white10),
                    ),
                    child: Row(
                      mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                      children: [
                        IconButton(
                          icon: Icon(
                            callState.isMuted ? Icons.mic_off : Icons.mic,
                            color: callState.isMuted ? Colors.redAccent : Colors.white,
                          ),
                          onPressed: () => callNotifier.toggleMute(),
                        ),
                        if (callState.isVideo) ...[
                          IconButton(
                            icon: Icon(
                              callState.isCameraOff ? Icons.videocam_off : Icons.videocam,
                              color: callState.isCameraOff ? Colors.redAccent : Colors.white,
                            ),
                            onPressed: () => callNotifier.toggleCamera(),
                          ),
                          IconButton(
                            icon: const Icon(Icons.switch_camera, color: Colors.white),
                            onPressed: () => callNotifier.switchCamera(),
                          ),
                        ],
                        IconButton(
                          icon: Icon(
                            callState.isSpeakerphone ? Icons.volume_up : Icons.volume_down,
                            color: callState.isSpeakerphone ? const Color(0xFF8A5CFF) : Colors.white,
                          ),
                          onPressed: () => callNotifier.toggleSpeakerphone(),
                        ),
                        const SizedBox(width: 8),
                        FloatingActionButton.small(
                          heroTag: 'end_call',
                          backgroundColor: Colors.red,
                          onPressed: () => callNotifier.hangup(),
                          child: const Icon(Icons.call_end, color: Colors.white),
                        ),
                      ],
                    ),
                  ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class VoiceWaveformPainter extends CustomPainter {
  final List<double> amplitudeHistory;
  final Color color;

  VoiceWaveformPainter({required this.amplitudeHistory, required this.color});

  @override
  void paint(Canvas canvas, Size size) {
    final paint = Paint()
      ..color = color
      ..strokeWidth = 3
      ..strokeCap = StrokeCap.round;

    final double midY = size.height / 2;
    final double spacing = size.width / 40;

    for (int i = 0; i < amplitudeHistory.length; i++) {
      final double x = i * spacing;
      final double level = amplitudeHistory[i];
      final double barHeight = size.height * level * 0.8;
      
      canvas.drawLine(
        Offset(x, midY - barHeight / 2),
        Offset(x, midY + barHeight / 2),
        paint,
      );
    }
  }

  @override
  bool shouldRepaint(covariant VoiceWaveformPainter oldDelegate) => true;
}
