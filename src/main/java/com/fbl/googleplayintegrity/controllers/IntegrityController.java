package com.fbl.googleplayintegrity.controllers;

import com.fbl.googleplayintegrity.dto.IntegrityDTO;
import com.fbl.googleplayintegrity.dto.NonceDTO;
import com.fbl.googleplayintegrity.services.IntegrityService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

@RestController
public class IntegrityController {

    private final IntegrityService integrityService;

    @Autowired
    public IntegrityController(IntegrityService integrityService) {
        this.integrityService = integrityService;
    }

    @GetMapping("/nonce")
    public NonceDTO nonce() {
        return this.integrityService.createNonce();
    }

    @GetMapping("/decryptRemote")
    public Optional<IntegrityDTO> decryptRemote(String originalNonce, String integrityEncryptedToken) {
        return this.integrityService.decryptRemote(originalNonce, integrityEncryptedToken);
    }

    @GetMapping("/decryptLocally")
    public Optional<IntegrityDTO> decryptLocally(String originalNonce, String integrityEncryptedToken) {
        return this.integrityService.decryptLocally(originalNonce, integrityEncryptedToken);
    }
}
