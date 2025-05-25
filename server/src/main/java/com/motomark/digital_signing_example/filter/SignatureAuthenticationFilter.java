package com.motomark.digital_signing_example.filter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;
import java.util.List;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.motomark.digital_signing_example.store.ClientKeyStore;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class SignatureAuthenticationFilter extends OncePerRequestFilter {

    private final ClientKeyStore keyStore;

    public SignatureAuthenticationFilter(ClientKeyStore keyStore) {
        this.keyStore = keyStore;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {


        // 1. This is the base64 encoded signature sent via the client of the request method, request path, and date. 
        // Signed using the clients private key.
        String signatureHeader = request.getHeader("X-Signature");

        // 2. This is the key id in our keystore map to the public key.
        String keyId = request.getHeader("X-Key-Id");
        String dateHeader = request.getHeader("Date");

        if (signatureHeader == null || keyId == null || dateHeader == null) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Missing authentication headers");
            return;
        }

        String signingString = request.getMethod() + "\n" + request.getRequestURI() + "\n" + dateHeader;
        PublicKey publicKey = keyStore.getPublicKey(keyId);

        if (publicKey == null) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unknown key ID");
            return;
        }

        try {
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(publicKey);
            sig.update(signingString.getBytes(StandardCharsets.UTF_8));
            //System.out.println("Sig verify: "+new String(sig.sign()));

            boolean valid = sig.verify(Base64.getDecoder().decode(signatureHeader));

            if (!valid) {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid signature");
                return;
            }

            Authentication auth = new UsernamePasswordAuthenticationToken(
                    keyId, null, List.of(() -> "ROLE_CLIENT"));
            SecurityContextHolder.getContext().setAuthentication(auth);
        } catch (Exception e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Signature verification error");
            return;
        }

        chain.doFilter(request, response);
    }
}

