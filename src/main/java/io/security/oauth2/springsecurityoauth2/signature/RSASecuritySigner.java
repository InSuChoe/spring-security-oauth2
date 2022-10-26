package io.security.oauth2.springsecurityoauth2.signature;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.security.core.userdetails.UserDetails;

import javax.crypto.SecretKey;
import java.security.interfaces.RSAPrivateKey;

public class RSASecuritySigner extends SecuritySigner{
    @Override
    public String getJwtToken(UserDetails user, JWK jwk) throws JOSEException {
        RSAKey rsaKey = (RSAKey) jwk;
        RSAPrivateKey rsaPrivateKey = rsaKey.toRSAPrivateKey();

        RSASSASigner jwsSigner=new RSASSASigner(rsaPrivateKey);
        return super.getJwtTokenInternal(jwsSigner, user, jwk);
    }


}
