// frontend/lib/infrastructure/auth_api_client.dart

import 'dart:convert';
import 'package:http/http.dart' as http;
import '../domain/auth_models.dart';

class AuthApiClient {
  final String baseUrl;
  final http.Client _client;

  AuthApiClient({
    required this.baseUrl,
    http.Client? client,
  }) : _client = client ?? http.Client();

  Future<LocalSessionPackage> register({
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
    final url = Uri.parse('$baseUrl/api/v1/auth/register');
    final response = await _client.post(
      url,
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'username': username,
        'password': password,
        'recovery_mnemonic': recoveryMnemonic,
        'display_name': displayName.isEmpty ? null : displayName,
        'device_name': deviceName,
        'device_type': deviceType,
        'platform': platform,
        'app_version': appVersion,
        'device_public_key': devicePublicKey,
        'verification_fingerprint': verificationFingerprint,
      }),
    );

    if (response.statusCode != 200) {
      throw Exception(response.body);
    }

    final data = jsonDecode(response.body) as Map<String, dynamic>;
    final credentials = UserCredentials.fromJson(data);
    final session = UserSession.fromJson(data);

    return LocalSessionPackage(credentials: credentials, session: session);
  }

  Future<LocalSessionPackage> login({
    required String identifier,
    required String password,
    required String deviceName,
    required String deviceType,
    required String platform,
    required String appVersion,
    required List<int> devicePublicKey,
    required String verificationFingerprint,
  }) async {
    final url = Uri.parse('$baseUrl/api/v1/auth/login');
    final response = await _client.post(
      url,
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'identifier': identifier,
        'password': password,
        'device_name': deviceName,
        'device_type': deviceType,
        'platform': platform,
        'app_version': appVersion,
        'device_public_key': devicePublicKey,
        'verification_fingerprint': verificationFingerprint,
      }),
    );

    if (response.statusCode != 200) {
      throw Exception(response.body);
    }

    final data = jsonDecode(response.body) as Map<String, dynamic>;
    final credentials = UserCredentials.fromJson(data);
    final session = UserSession.fromJson(data);

    return LocalSessionPackage(credentials: credentials, session: session);
  }

  Future<UserSession> refresh(String refreshToken) async {
    final url = Uri.parse('$baseUrl/api/v1/auth/refresh');
    final response = await _client.post(
      url,
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'refresh_token': refreshToken}),
    );

    if (response.statusCode != 200) {
      throw Exception(response.body);
    }

    final data = jsonDecode(response.body) as Map<String, dynamic>;
    return UserSession.fromJson(data);
  }

  Future<void> recover({
    required String identifier,
    required String recoveryMnemonic,
    required String newPassword,
  }) async {
    final url = Uri.parse('$baseUrl/api/v1/auth/recover');
    final response = await _client.post(
      url,
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'identifier': identifier,
        'recovery_mnemonic': recoveryMnemonic,
        'new_password': newPassword,
      }),
    );

    if (response.statusCode != 200) {
      throw Exception(response.body);
    }
  }

  Future<void> logout(String refreshToken) async {
    final url = Uri.parse('$baseUrl/api/v1/auth/logout');
    final response = await _client.post(
      url,
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'refresh_token': refreshToken}),
    );

    if (response.statusCode != 200) {
      throw Exception(response.body);
    }
  }
}
