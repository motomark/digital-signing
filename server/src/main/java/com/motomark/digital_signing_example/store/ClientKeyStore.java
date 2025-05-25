package com.motomark.digital_signing_example.store;

import java.io.File;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.springframework.stereotype.Component;
import org.springframework.util.ResourceUtils;

@Component
public class ClientKeyStore {

    private final Map<String, PublicKey> keys = new HashMap<>();

    public ClientKeyStore() {
        // In real apps, load from DB or keystore
        try {
            keys.put("client-123", loadPublicKey("client-public.pem"));
        } catch (Exception e) {
            throw new RuntimeException("Failed to load keys", e);
        }
    }

    public PublicKey getPublicKey(String keyId) {
        return keys.get(keyId);
    }

    private PublicKey loadPublicKey(String filename) throws Exception {
        String key = new String(Files.readAllBytes(ResourceUtils.getFile("classpath:"+filename).toPath()))
                .replaceAll("-----\\w+ PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        byte[] keyBytes = Base64.getDecoder().decode(key);
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(keyBytes));
    }
}
