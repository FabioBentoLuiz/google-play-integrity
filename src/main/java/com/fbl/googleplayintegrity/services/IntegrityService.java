package com.fbl.googleplayintegrity.services;

import com.fbl.googleplayintegrity.dto.IntegrityDTO;
import com.fbl.googleplayintegrity.dto.NonceDTO;
import com.google.api.client.googleapis.services.GoogleClientRequestInitializer;
import com.google.api.client.http.HttpRequestInitializer;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.services.playintegrity.v1.PlayIntegrity;
import com.google.api.services.playintegrity.v1.PlayIntegrityRequestInitializer;
import com.google.api.services.playintegrity.v1.model.DecodeIntegrityTokenRequest;
import com.google.api.services.playintegrity.v1.model.DecodeIntegrityTokenResponse;
import com.google.api.services.playintegrity.v1.model.TokenPayloadExternal;
import com.google.auth.http.HttpCredentialsAdapter;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwx.JsonWebStructure;
import org.jose4j.lang.JoseException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import static org.apache.http.util.Asserts.notEmpty;
import static org.springframework.util.Assert.notNull;

@Service
public class IntegrityService {

    @Value("${integrity.package}")
    private String packageName;

    @Value("${integrity.application}")
    private String applicationName;

    @Value("${integrity.credentials}")
    private String integrityCredentials;

    @Value("${integrity.decryption.key}")
    private String base64OfEncodedDecryptionKey;

    @Value("${integrity.verification.key}")
    private String base64OfEncodedVerificationKey;

    private static final String AES_KEY_TYPE = "AES";

    private static final String ELLIPTIC_CURVE_KEY_TYPE = "EC";

    private HttpTransport httpTransport = new NetHttpTransport();

    private static final JsonFactory JSON_FACTORY = new JacksonFactory();

    private static final SecureRandom NONCE_RANDOM = new SecureRandom();

    public Optional<IntegrityDTO> decryptRemote(String originalNonce, String integrityEncryptedToken) {

        validateParameters(originalNonce, integrityEncryptedToken);

        DecodeIntegrityTokenRequest requestObj = new DecodeIntegrityTokenRequest();
        requestObj.setIntegrityToken(integrityEncryptedToken);

        GoogleCredentials credentials = getGoogleCredentials();
        HttpRequestInitializer requestInitializer = new HttpCredentialsAdapter(credentials);

        GoogleClientRequestInitializer initialiser = new PlayIntegrityRequestInitializer();

        PlayIntegrity.Builder playIntegrity = new PlayIntegrity
                .Builder(httpTransport, JSON_FACTORY, requestInitializer)
                .setApplicationName(applicationName)
                .setGoogleClientRequestInitializer(initialiser);
        PlayIntegrity play = playIntegrity.build();

        DecodeIntegrityTokenResponse response = getDecodeIntegrityTokenResponse(play, requestObj);

        IntegrityDTO integrityDTO = getIntegrityDTO(response.getTokenPayloadExternal());
        checkNonce(integrityDTO, originalNonce);
        return Optional.of(integrityDTO);
    }

    private void validateParameters(String originalNonce, String integrityEncryptedToken) {
        notEmpty(integrityEncryptedToken, "Integrity Token is mandatory");
        notEmpty(originalNonce, "Nonce is mandatory");
    }

    public Optional<IntegrityDTO> decryptLocally(String originalNonce, String integrityEncryptedToken) {
        validateParameters(originalNonce, integrityEncryptedToken);

        String compactJws = getJavaWebSignature(integrityEncryptedToken);

        PublicKey verificationKey = getVerificationKey();

        String jsonPayload = parsePayload(compactJws, verificationKey);

        IntegrityDTO integrity = getIntegrityResponse(jsonPayload);

        return Optional.of(integrity);
    }

    private DecodeIntegrityTokenResponse getDecodeIntegrityTokenResponse(PlayIntegrity play, DecodeIntegrityTokenRequest requestObj) {
        try {
            DecodeIntegrityTokenResponse response = play.v1().decodeIntegrityToken(packageName, requestObj).execute();
            return response;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private GoogleCredentials getGoogleCredentials() {
        try {
            byte[] decodedCredentials = Base64.getUrlDecoder().decode(integrityCredentials);
            ByteArrayInputStream stream = new ByteArrayInputStream(decodedCredentials);
            return GoogleCredentials.fromStream(stream);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void checkNonce(IntegrityDTO integrityDTO, String originalNonce) {
        if (!integrityDTO.nonce().equals(originalNonce)) {
            throw new RuntimeException("The given nonce differ from the original one.");
        }
    }

    private String getJavaWebSignature(String integrityEncryptedToken) {
        String compactJws;

        try {
            JsonWebEncryption jwe = (JsonWebEncryption) JsonWebStructure.fromCompactSerialization(integrityEncryptedToken);
            byte[] decryptionKeyBytes = Base64.getDecoder().decode(base64OfEncodedDecryptionKey);
            SecretKey decryptionKey = new SecretKeySpec(decryptionKeyBytes, AES_KEY_TYPE);

            jwe.setKey(decryptionKey);

            compactJws = jwe.getPayload();
        } catch (JoseException e) {
            throw new RuntimeException(e);
        }

        return compactJws;
    }

    public PublicKey getVerificationKey() {
        byte[] encodedVerificationKey = Base64.getUrlDecoder().decode(base64OfEncodedVerificationKey);
        PublicKey verificationKey;
        try {
            verificationKey = KeyFactory.getInstance(ELLIPTIC_CURVE_KEY_TYPE).generatePublic(new X509EncodedKeySpec(encodedVerificationKey));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        return verificationKey;
    }

    private String parsePayload(String compactJws, PublicKey verificationKey) {
        String payload;

        try {
            JsonWebSignature jws = (JsonWebSignature) JsonWebStructure.fromCompactSerialization(compactJws);
            jws.setKey(verificationKey);
            payload = jws.getPayload();
        } catch (JoseException e) {
            throw new RuntimeException(e);
        }

        return payload;
    }

    private IntegrityDTO getIntegrityResponse(String payload) {
        JsonObject objPayload = parseJsonObject(payload);

        JsonObject requestDetails = objPayload.get("requestDetails").getAsJsonObject();
        JsonObject appIntegrity = objPayload.get("appIntegrity").getAsJsonObject();
        JsonObject deviceIntegrity = objPayload.get("deviceIntegrity").getAsJsonObject();

        IntegrityDTO integrityDTO = new IntegrityDTO(requestDetails.get("timestampMillis").getAsLong(),
                requestDetails.get("nonce").getAsString(),
                convertToList(appIntegrity.get("certificateSha256Digest").getAsJsonArray()),
                convertToList(deviceIntegrity.get("deviceRecognitionVerdict").getAsJsonArray()));

        return integrityDTO;
    }

    private List<String> convertToList(JsonArray jsonArray) {
        List<String> list = new ArrayList<>();
        jsonArray.forEach(i -> list.add(i.getAsString()));
        return list;
    }

    private JsonObject parseJsonObject(String payload) {
        JsonObject objPayload = new Gson().fromJson(payload, JsonObject.class);

        notNull(objPayload.get("requestDetails"), "Payload with 'requestDetails' field is mandatory.");
        notNull(objPayload.get("appIntegrity"), "Payload with 'appIntegrity' field is mandatory.");
        notNull(objPayload.get("deviceIntegrity"), "Payload with 'deviceIntegrity' field is mandatory.");

        return objPayload;
    }

    private IntegrityDTO getIntegrityDTO(TokenPayloadExternal tokenPayloadExternal) {
        IntegrityDTO integrityDTO = new IntegrityDTO(tokenPayloadExternal.getRequestDetails().getTimestampMillis(),
                tokenPayloadExternal.getRequestDetails().getNonce(),
                tokenPayloadExternal.getAppIntegrity().getCertificateSha256Digest(),
                tokenPayloadExternal.getDeviceIntegrity().getDeviceRecognitionVerdict());

        return integrityDTO;
    }

    public NonceDTO createNonce() {
        byte[] bytes = new byte[24];
        NONCE_RANDOM.nextBytes(bytes);
        String nonce = Base64
                .getUrlEncoder()
                .withoutPadding()
                .encodeToString(bytes);
        return new NonceDTO(nonce);
    }
}
