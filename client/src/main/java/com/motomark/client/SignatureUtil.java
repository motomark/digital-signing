package com.motomark.client;

import java.security.PrivateKey;
import java.security.Signature;
import java.util.Base64;

public class SignatureUtil {
    public static String sign(String data, PrivateKey privateKey) throws Exception {
        Signature rsa = Signature.getInstance("SHA256withRSA");
        rsa.initSign(privateKey);
        rsa.update(data.getBytes());
        byte[] signature = rsa.sign();
        return Base64.getEncoder().encodeToString(signature);
    }
}