// frontend/lib/application/auth_provider.dart

import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../domain/auth_models.dart';
import '../infrastructure/auth_api_client.dart';

// Represents all states of authentication flow
abstract class AuthState {
  const AuthState();
}

class AuthInitial extends AuthState {
  const AuthInitial();
}

class AuthLoading extends AuthState {
  const AuthLoading();
}

class AuthSuccess extends AuthState {
  final UserCredentials credentials;
  final UserSession session;

  const AuthSuccess({
    required this.credentials,
    required this.session,
  });
}

class AuthFailure extends AuthState {
  final String error;

  const AuthFailure(this.error);
}

class RecoverySuccess extends AuthState {
  const RecoverySuccess();
}

class AuthNotifier extends StateNotifier<AuthState> {
  final AuthApiClient _api;
  
  // Safe in-memory store for session mock.
  // In production, integrate package:flutter_secure_storage
  LocalSessionPackage? _currentSession;

  AuthNotifier({required AuthApiClient api})
      : _api = api,
        super(const AuthInitial());

  LocalSessionPackage? get currentSession => _currentSession;

  Future<void> register({
    required String username,
    required String password,
    required String recoveryMnemonic,
    required String displayName,
    required String deviceName,
    required String deviceType,
    required String platform,
    required String appVersion,
    required List<int> devicePublicKey,
    required String verificationFingerprint,
  }) async {
    state = const AuthLoading();
    try {
      final sessionPkg = await _api.register(
        username: username,
        password: password,
        recoveryMnemonic: recoveryMnemonic,
        displayName: displayName,
        deviceName: deviceName,
        deviceType: deviceType,
        platform: platform,
        appVersion: appVersion,
        devicePublicKey: devicePublicKey,
        verificationFingerprint: verificationFingerprint,
      );
      _currentSession = sessionPkg;
      state = AuthSuccess(
        credentials: sessionPkg.credentials,
        session: sessionPkg.session,
      );
    } catch (e) {
      state = AuthFailure(e.toString());
    }
  }

  Future<void> login({
    required String identifier,
    required String password,
    required String deviceName,
    required String deviceType,
    required String platform,
    required String appVersion,
    required List<int> devicePublicKey,
    required String verificationFingerprint,
  }) async {
    state = const AuthLoading();
    try {
      final sessionPkg = await _api.login(
        identifier: identifier,
        password: password,
        deviceName: deviceName,
        deviceType: deviceType,
        platform: platform,
        appVersion: appVersion,
        devicePublicKey: devicePublicKey,
        verificationFingerprint: verificationFingerprint,
      );
      _currentSession = sessionPkg;
      state = AuthSuccess(
        credentials: sessionPkg.credentials,
        session: sessionPkg.session,
      );
    } catch (e) {
      state = AuthFailure(e.toString());
    }
  }

  Future<void> rotateSession() async {
    final sessionPkg = _currentSession;
    if (sessionPkg == null) {
      state = const AuthInitial();
      return;
    }

    try {
      final newSession = await _api.refresh(sessionPkg.session.refreshToken);
      _currentSession = LocalSessionPackage(
        credentials: sessionPkg.credentials,
        session: newSession,
      );
      state = AuthSuccess(
        credentials: sessionPkg.credentials,
        session: newSession,
      );
    } catch (e) {
      // Invalidation triggers forced logout and transition to initial state
      _currentSession = null;
      state = AuthFailure("Session expired: ${e.toString()}");
    }
  }

  Future<void> recover({
    required String identifier,
    required String recoveryMnemonic,
    required String newPassword,
  }) async {
    state = const AuthLoading();
    try {
      await _api.recover(
        identifier: identifier,
        recoveryMnemonic: recoveryMnemonic,
        newPassword: newPassword,
      );
      state = const RecoverySuccess();
    } catch (e) {
      state = AuthFailure(e.toString());
    }
  }

  Future<void> logout() async {
    final sessionPkg = _currentSession;
    state = const AuthLoading();
    if (sessionPkg != null) {
      try {
        await _api.logout(sessionPkg.session.refreshToken);
      } catch (_) {
        // Suppress failure and force clear local state anyway
      }
    }
    _currentSession = null;
    state = const AuthInitial();
  }
}

// Providers definition
final authApiClientProvider = Provider<AuthApiClient>((ref) {
  return AuthApiClient(baseUrl: 'http://localhost:8080');
});

final authProvider = StateNotifierProvider<AuthNotifier, AuthState>((ref) {
  final api = ref.watch(authApiClientProvider);
  return AuthNotifier(api: api);
});
