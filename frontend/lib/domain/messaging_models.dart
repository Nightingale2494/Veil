// frontend/lib/domain/messaging_models.dart

import 'dart:typed_data';

enum MessageType {
  text(0),
  image(1),
  video(2),
  voice(3),
  receipt(4),
  typing(5),
  reaction(6),
  system(7);

  final int value;
  const MessageType(this.value);

  static MessageType fromInt(int val) {
    return MessageType.values.firstWhere(
      (e) => e.value == val,
      orElse: () => MessageType.text,
    );
  }
}

class ClientEnvelope {
  final String messageId;
  final String conversationId;
  final String senderDeviceId;
  final String recipientDeviceId;
  final int timestamp; // Milliseconds Unix epoch
  final Uint8List dhPub;
  final Uint8List ciphertext;
  final Uint8List signature;
  final int majorVersion;
  final int minorVersion;
  final int messageNumber;

  ClientEnvelope({
    required this.messageId,
    required this.conversationId,
    required this.senderDeviceId,
    required this.recipientDeviceId,
    required this.timestamp,
    required this.dhPub,
    required this.ciphertext,
    required this.signature,
    required this.majorVersion,
    required this.minorVersion,
    required this.messageNumber,
  });

  Map<String, dynamic> toJson() {
    return {
      'message_id': messageId,
      'conversation_id': conversationId,
      'sender_device_id': senderDeviceId,
      'recipient_device_id': recipientDeviceId,
      'timestamp': timestamp,
      'dh_pub': dhPub,
      'ciphertext': ciphertext,
      'signature': signature,
      'major_version': majorVersion,
      'minor_version': minorVersion,
      'message_number': messageNumber,
    };
  }
}

class DecryptedPayload {
  final MessageType type;
  final Uint8List content;

  DecryptedPayload({
    required this.type,
    required this.content,
  });
}
