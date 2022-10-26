package io.security.oauth2.springsecurityoauth2.signature;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

public abstract class SecuritySigner {
    public abstract String getJwtToken(UserDetails user, JWK jwk) throws JOSEException;

    protected String getJwtTokenInternal(JWSSigner jwsSigner, UserDetails user, JWK jwk) throws JOSEException {
        JWSAlgorithm algorithm = (JWSAlgorithm) jwk.getAlgorithm();
        JWSHeader.Builder headerBuilder = new JWSHeader.Builder(algorithm);
        JWSHeader header = headerBuilder.keyID(jwk.getKeyID()).build();
        List<String> authorities = user.getAuthorities().stream().map(auth -> auth.getAuthority()).collect(Collectors.toList());

        JWTClaimsSet.Builder cliamsSetBuilder = new JWTClaimsSet.Builder();
        final int FIVE_MINUTE = 60 * 1000 * 5;
        final long NOW_TIME = new Date().getTime();
        JWTClaimsSet claimsSet = cliamsSetBuilder.subject("user").issuer("http://localhost:8081")
                .claim("username", user.getUsername())
                .claim("authority", authorities)
                .expirationTime(new Date(NOW_TIME + FIVE_MINUTE)).build();

        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        signedJWT.sign(jwsSigner);
        String jwtToken = signedJWT.serialize();

        return jwtToken;
    }
}
