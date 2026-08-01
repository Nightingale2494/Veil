// frontend/lib/infrastructure/ws_client.dart

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

class VeilWebSocketClient {
  final Uri wsUri;
  final String accessToken;
  
  WebSocket? _socket;
  bool _isClosedIntentionally = false;
  int _reconnectDelaySeconds = 1;
  Timer? _heartbeatTimer;
  DateTime _lastHeartbeat = DateTime.now();

  final _messageController = StreamController<Uint8List>.broadcast();
  final _connectionStateController = StreamController<bool>.broadcast();

  VeilWebSocketClient({
    required this.wsUri,
    required this.accessToken,
  });

  Stream<Uint8List> get messages => _messageController.stream;
  Stream<bool> get connectionState => _connectionStateController.stream;

  Future<void> connect() async {
    _isClosedIntentionally = false;
    try {
      // Connect using Sec-WebSocket-Protocol header to transmit access token securely
      _socket = await WebSocket.connect(
        wsUri.toString(),
        protocols: [accessToken],
      );

      _reconnectDelaySeconds = 1; // Reset back-off on success
      _connectionStateController.add(true);
      _lastHeartbeat = DateTime.now();

      _socket!.listen(
        (data) {
          _lastHeartbeat = DateTime.now();
          if (data is List<int>) {
            _messageController.add(Uint8List.fromList(data));
          } else if (data is String) {
            if (data == 'pong') {
              // Heartbeat verified
            }
          }
        },
        onError: (err) {
          _handleDisconnect();
        },
        onDone: () {
          _handleDisconnect();
        },
      );

      // Start ping heartbeat checks (ping every 30s)
      _startHeartbeat();

    } catch (e) {
      _handleDisconnect();
    }
  }

  void _startHeartbeat() {
    _heartbeatTimer?.cancel();
    _heartbeatTimer = Timer.periodic(const Duration(seconds: 30), (timer) {
      if (_socket == null) return;
      
      final now = DateTime.now();
      if (now.difference(_lastHeartbeat).inSeconds > 90) {
        // Heartbeat timeout: force disconnect
        _socket!.close();
        _handleDisconnect();
        return;
      }

      // Send Ping frame
      _socket!.addString('ping');
    });
  }

  void _handleDisconnect() {
    _heartbeatTimer?.cancel();
    _socket = null;
    _connectionStateController.add(false);

    if (!_isClosedIntentionally) {
      // Exponential back-off delay capped at 30 seconds
      Timer(Duration(seconds: _reconnectDelaySeconds), () {
        _reconnectDelaySeconds = (_reconnectDelaySeconds * 2).clamp(1, 30);
        connect();
      });
    }
  }

  void sendEnvelope(Uint8List envelopeBytes) {
    if (_socket != null && _socket!.readyState == WebSocket.open) {
      _socket!.add(envelopeBytes);
    }
  }

  void sendTypingIndicator(Uint8List indicatorBytes) {
    if (_socket != null && _socket!.readyState == WebSocket.open) {
      _socket!.add(indicatorBytes);
    }
  }

  void disconnect() {
    _isClosedIntentionally = true;
    _heartbeatTimer?.cancel();
    _socket?.close();
    _socket = null;
    _connectionStateController.add(false);
  }
}
