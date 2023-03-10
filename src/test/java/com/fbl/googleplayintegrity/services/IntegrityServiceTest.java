package com.fbl.googleplayintegrity.services;

import com.fbl.googleplayintegrity.dto.IntegrityDTO;
import com.fbl.googleplayintegrity.dto.NonceDTO;
import com.google.api.client.http.LowLevelHttpRequest;
import com.google.api.client.http.LowLevelHttpResponse;
import com.google.api.client.json.Json;
import com.google.api.client.testing.http.MockHttpTransport;
import com.google.api.client.testing.http.MockLowLevelHttpRequest;
import com.google.api.client.testing.http.MockLowLevelHttpResponse;
import com.google.api.services.playintegrity.v1.model.AppIntegrity;
import com.google.api.services.playintegrity.v1.model.DeviceIntegrity;
import com.google.api.services.playintegrity.v1.model.RequestDetails;
import com.google.api.services.playintegrity.v1.model.TokenPayloadExternal;
import com.google.gson.Gson;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.JoseException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers.AES_256_GCM;
import static org.jose4j.jwe.KeyManagementAlgorithmIdentifiers.A256KW;
import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class IntegrityServiceTest {
    @Autowired
    private IntegrityService integrityService;

    @Test
    void nonceShouldNotBeNull() {
        NonceDTO nonce = integrityService.createNonce();
        assertNotNull(nonce);
        assertNotNull(nonce.nonce());
    }

    @Test
    void nonceShouldNotBeDuplicated() {
        NonceDTO n1 = integrityService.createNonce();
        NonceDTO n2 = integrityService.createNonce();
        assertNotEquals(n1, n2);
    }

    @Test
    void throwsIllegalStateExceptionIfNonceIsEmpty() {
        assertThrows(IllegalStateException.class, () -> integrityService.decryptRemote("", "encrypted-payload"));
    }

    @Test
    void throwsIllegalStateExceptionIfPayloadIsEmpty() {
        assertThrows(IllegalStateException.class, () -> integrityService.decryptRemote("my-nonce", ""));
    }

    @Test
    void remoteDecryptOnGoogleServersShouldBeSuccessfull() {
        ReflectionTestUtils.setField(integrityService, "httpTransport", getHttpMock());
        Optional<IntegrityDTO> response = integrityService.decryptRemote("SafetyNetSample1654058651834", "my-token");
        assertTrue(response.isPresent());
        assertEquals("SafetyNetSample1654058651834", response.get().nonce());
        assertEquals("MEETS_DEVICE_INTEGRITY", response.get().deviceRecognitionVerdict().get(0));
        assertEquals(1654058657132L, response.get().timestampMillis());
        assertEquals("pnpa8e8eCArtvmaf49bJE1f5iG5-XLSU6w1U9ZvI96g", response.get().certificateSha256Digest().get(0));
    }

    @Test
    void throwsRunntimeExceptionWhenTheOriginalNonceDoNotMatch() {
        ReflectionTestUtils.setField(integrityService, "httpTransport", getHttpMock());
        assertThrows(RuntimeException.class, () -> integrityService.decryptRemote("falsch-nonce", "my-token"));
    }

    private MockHttpTransport getHttpMock() {
        return new MockHttpTransport() {
            @Override
            public LowLevelHttpRequest buildRequest(String method, String url) throws IOException {
                return new MockLowLevelHttpRequest() {
                    @Override
                    public LowLevelHttpResponse execute() throws IOException {
                        MockLowLevelHttpResponse response = new MockLowLevelHttpResponse();
                        response.addHeader("custom_header", "value");
                        response.setStatusCode(200);
                        response.setContentType(Json.MEDIA_TYPE);
                        response.setContent("""
                                {
                                  "tokenPayloadExternal": {
                                    "accountDetails": {
                                        "appLicensingVerdict": "LICENSED"
                                    },
                                    "appIntegrity": {
                                        "appRecognitionVerdict": "PLAY_RECOGNIZED",
                                        "certificateSha256Digest": ["pnpa8e8eCArtvmaf49bJE1f5iG5-XLSU6w1U9ZvI96g"],
                                        "packageName": "com.test.android.integritysample",
                                        "versionCode": "4"
                                    },
                                    "deviceIntegrity": {
                                        "deviceRecognitionVerdict": ["MEETS_DEVICE_INTEGRITY"]
                                    },
                                    "requestDetails": {
                                        "nonce": "SafetyNetSample1654058651834",
                                        "requestPackageName": "com.test.android.integritysample",
                                        "timestampMillis": "1654058657132"
                                    }
                                  }
                                }""");
                        return response;
                    }
                };
            }
        };
    }

    /**
     * The token is a nested JSON Web Token (JWT), that is JSON Web Encryption (JWE) of JSON Web Signature (JWS).
     * The JWE and JWS components are represented using compact serialization.
     * The encryption / signing algorithms are well-supported across various JWT implementations:
     * - JWE uses A256KW for alg and A256GCM for enc.
     * - JWS uses ES256.
     * https://developer.android.com/google/play/integrity/verdict#decrypt-verify
     */
    @Test
    void localDecryptShouldBeSuccessfull() throws JoseException {
        String nonce = "abc";

        String payload = getGoogleIntegrtyPayload(nonce);

        JsonWebSignature jws = getJws(payload);

        JsonWebEncryption jwe = getJwe(jws);

        String compactSerialization = jwe.getCompactSerialization();

        Optional<IntegrityDTO> response = integrityService.decryptLocally(nonce, compactSerialization);
        assertTrue(response.isPresent());
        assertEquals(nonce, response.get().nonce());
        assertEquals("6a6a1474b5cbbb2b1aa57e0bc3", response.get().certificateSha256Digest().get(0));
        assertEquals("MEETS_DEVICE_INTEGRITY", response.get().deviceRecognitionVerdict().get(0));
    }


    private JsonWebEncryption getJwe(JsonWebSignature jws) throws JoseException {
        //Example from https://github.com/felx/jose4j/blob/master/src/test/java/org/jose4j/cookbook/JoseCookbookTest.java
        String jwkJson = """
                   {
                     "kty": "oct",
                     "kid": "1e571774-2e08-40da-8308-e8d68773842d",
                     "use": "enc",
                     "alg": "A256GCM",
                     "k": "Xf9wKWThntvK9vE4jjjXOekULEMNXwbeYIN5nK3dh5w"
                   }""";
        JsonWebKey jwk = JsonWebKey.Factory.newJwk(jwkJson);

        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setPlaintext(jws.getCompactSerialization());
        jwe.setAlgorithmHeaderValue(A256KW);
        jwe.setEncryptionMethodHeaderParameter(AES_256_GCM);
        jwe.setKey(jwk.getKey());

        return jwe;
    }

    private JsonWebSignature getJws(String payload) throws JoseException {
        //Using key from http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-13#appendix-A.3.1
        String jwkJson = """
                {
                 "kty":"EC",
                 "crv":"P-256",
                 "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                 "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
                 "d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"
                }""";
        JsonWebKey ecJwk = JsonWebKey.Factory.newJwk(jwkJson);
        PublicJsonWebKey pubJwk = (PublicJsonWebKey) ecJwk;

        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(payload);
        jws.setKey(pubJwk.getPrivateKey());
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);

        return jws;
    }

    private String getGoogleIntegrtyPayload(String nonce) {
        TokenPayloadExternal token = new TokenPayloadExternal();

        RequestDetails requestDetails = new RequestDetails();
        requestDetails.setNonce(nonce);
        requestDetails.setTimestampMillis(System.currentTimeMillis());

        AppIntegrity appIntegrity = new AppIntegrity();
        List<String> certificates = new ArrayList<>();
        certificates.add("6a6a1474b5cbbb2b1aa57e0bc3");
        appIntegrity.setCertificateSha256Digest(certificates);

        DeviceIntegrity deviceIntegrity = new DeviceIntegrity();
        List<String> veredicts = new ArrayList<>();
        veredicts.add("MEETS_DEVICE_INTEGRITY");
        deviceIntegrity.setDeviceRecognitionVerdict(veredicts);

        token.setRequestDetails(requestDetails);
        token.setAppIntegrity(appIntegrity);
        token.setDeviceIntegrity(deviceIntegrity);

        return new Gson().toJson(token);
    }
}