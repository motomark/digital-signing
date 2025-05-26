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

        // 3. This is the date when the request was sent.
        String dateHeader = request.getHeader("Date");

        if (signatureHeader == null || keyId == null || dateHeader == null) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Missing authentication headers");
            return;
        }

        // 4. Re-create the signing string in the same way as the client before signing.
        String signingString = request.getMethod() + "\n" + request.getRequestURI() + "\n" + dateHeader;

        // 5. Obtain the public key from the keystore.
        PublicKey publicKey = keyStore.getPublicKey(keyId);

        if (publicKey == null) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unknown key ID");
            return;
        }

        try {
            Signature sig = Signature.getInstance("SHA256withRSA");
            // 6. Set the public key ready for verification.
            sig.initVerify(publicKey);
            
            // 7. use the signing string.
            sig.update(signingString.getBytes(StandardCharsets.UTF_8));
            
            // 8. Perform the validation e.g. pass in the signature we received in the request (decode it first) and verify that 
            // decrypting with the expected public key we get a matching signature.
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

