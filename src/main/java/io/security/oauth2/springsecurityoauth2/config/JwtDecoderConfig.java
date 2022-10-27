package io.security.oauth2.springsecurityoauth2.config;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import javax.crypto.SecretKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

@Configuration
public class JwtDecoderConfig {
    @Bean
    @ConditionalOnProperty(prefix = "spring.security.oauth2.resourceserver.jwt",
    name = "jws-algorithms", havingValue = "HS256", matchIfMissing = false)
    public JwtDecoder jwtDecoderBySecretKeyValue(OctetSequenceKey octetSequenceKey, OAuth2ResourceServerProperties properties){
        SecretKey secretKey = octetSequenceKey.toSecretKey();
        return NimbusJwtDecoder.withSecretKey(secretKey)
                .macAlgorithm(MacAlgorithm.from(properties.getJwt().getJwsAlgorithms().get(0)))
                .build();
    }

    @Bean
    @ConditionalOnProperty(prefix = "spring.security.oauth2.resourceserver.jwt",
            name = "jws-algorithms", havingValue = "RS256", matchIfMissing = false)
    public JwtDecoder jwtDecoderByPublicKeyValue(RSAKey rsaKey, OAuth2ResourceServerProperties properties) throws JOSEException {
        RSAPublicKey rsaPublicKey = rsaKey.toRSAPublicKey();
        return NimbusJwtDecoder.withPublicKey(rsaPublicKey)
                .signatureAlgorithm(SignatureAlgorithm.from(properties.getJwt().getJwsAlgorithms().get(0)))
                .build();

    }
}
