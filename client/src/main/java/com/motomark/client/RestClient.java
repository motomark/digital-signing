package com.motomark.client;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.TimeZone;



public class RestClient {
    private static final String SERVER_URL = "http://localhost:8080/secure-data";
    private static final String KEY_ID = "client-123"; // used by server to find the public key

    public static void main(String[] args) throws Exception {
        String method = "GET";
        String path = "/secure-data";
        String date = getCurrentHttpDate();

        String signingString = method + "\n" + path + "\n" + date;

        // Load private key (for real apps, use a keystore or encrypted file)
        PrivateKey privateKey = loadPrivateKey("client-private.pem");

        String signature = SignatureUtil.sign(signingString, privateKey);

        HttpURLConnection conn = (HttpURLConnection) new URL(SERVER_URL).openConnection();
        conn.setRequestMethod(method);
        conn.setRequestProperty("Date", date);
        conn.setRequestProperty("X-Signature", signature);
        conn.setRequestProperty("X-Key-Id", KEY_ID);

        int responseCode = conn.getResponseCode();
        System.out.println("Response Code: " + responseCode);
        BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        reader.lines().forEach(System.out::println);
    }

    private static PrivateKey loadPrivateKey(String filename) throws Exception {
        File f = new File(RestClient.class.getClassLoader().getResource(filename).getFile());
        String key = new String(Files.readAllBytes(f.toPath()))
                .replaceAll("-----\\w+ PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        byte[] keyBytes = Base64.getDecoder().decode(key);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        return KeyFactory.getInstance("RSA").generatePrivate(spec);
    }

    private static String getCurrentHttpDate() {
        SimpleDateFormat format = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss zzz");
        format.setTimeZone(TimeZone.getTimeZone("GMT"));
        return format.format(new Date());
    }
}