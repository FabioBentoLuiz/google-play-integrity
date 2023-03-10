package com.fbl.googleplayintegrity.dto;

import java.util.List;

public record IntegrityDTO(long timestampMillis, String nonce, List<String> certificateSha256Digest, List<String> deviceRecognitionVerdict) {
}
