// frontend/lib/domain/auth_models.dart

class UserCredentials {
  final String userId;
  final String username;
  final String accountId;
  final String deviceId;
  final String deviceApprovalStatus;

  UserCredentials({
    required this.userId,
    required this.username,
    required this.accountId,
    required this.deviceId,
    required this.deviceApprovalStatus,
  });

  factory UserCredentials.fromJson(Map<String, dynamic> json) {
    return UserCredentials(
      userId: json['user_id'] as String,
      username: json['username'] as String,
      accountId: json['account_id'] as String,
      deviceId: json['device_id'] as String,
      deviceApprovalStatus: json['device_approval_status'] as String,
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'user_id': userId,
      'username': username,
      'account_id': accountId,
      'device_id': deviceId,
      'device_approval_status': deviceApprovalStatus,
    };
  }
}

class UserSession {
  final String accessToken;
  final String refreshToken;
  final DateTime expiresAt;

  UserSession({
    required this.accessToken,
    required this.refreshToken,
    required this.expiresAt,
  });

  factory UserSession.fromJson(Map<String, dynamic> json) {
    return UserSession(
      accessToken: json['access_token'] as String,
      refreshToken: json['refresh_token'] as String,
      expiresAt: DateTime.parse(json['expires_at'] as String),
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'access_token': accessToken,
      'refresh_token': refreshToken,
      'expires_at': expiresAt.toIso8601String(),
    };
  }
}

class LocalSessionPackage {
  final UserCredentials credentials;
  final UserSession session;

  LocalSessionPackage({
    required this.credentials,
    required this.session,
  });
}
