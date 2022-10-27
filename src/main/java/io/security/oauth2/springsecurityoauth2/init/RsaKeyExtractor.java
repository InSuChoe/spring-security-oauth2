package io.security.oauth2.springsecurityoauth2.init;

import io.security.oauth2.springsecurityoauth2.signature.RSAPublicKeySecuritySigner;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import java.io.*;
import java.nio.charset.Charset;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
@Component
public class RsaKeyExtractor implements ApplicationRunner {
    @Autowired
    private RSAPublicKeySecuritySigner rsaPublicSecuritySigner;

    @Override
    public void run(ApplicationArguments args) throws Exception{

        final String DIRECTORY_PATH="/Users/insoochoi/Desktop/spring-security-oauth2/src/main/resources/certs";
        final String FILE_NAME="publicKey.txt";
        final String API_KEYS_NAME="apiKey.jks";

        File file = new File(DIRECTORY_PATH + "/" + FILE_NAME);

        try(FileInputStream inputStream = new FileInputStream(DIRECTORY_PATH + "/" + API_KEYS_NAME);
            OutputStreamWriter writer = new OutputStreamWriter(new FileOutputStream(file), Charset.defaultCharset());
        ) {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            int extensionIndex = API_KEYS_NAME.indexOf(".");
            final String ALIAS=API_KEYS_NAME.substring(0, extensionIndex);

            final char[] password = "pass1234".toCharArray();
            keyStore.load(inputStream, password);
            Key key=keyStore.getKey(ALIAS, password);

            if(key instanceof PrivateKey)
            {
                Certificate certificate = keyStore.getCertificate(ALIAS);
                PublicKey publicKey = certificate.getPublicKey();
                PrivateKey privateKey = (PrivateKey) key;
                KeyPair keyPair = new KeyPair(publicKey,privateKey);
                rsaPublicSecuritySigner.setPrivateKey(keyPair.getPrivate());

                if (!file.exists()) file.createNewFile();

                String publicStr=java.util.Base64.getMimeEncoder().encodeToString(publicKey.getEncoded());
                publicStr="-----BEGIN PUBLIC KEY-----\n" + publicStr +"\n-----END PUBLIC KEY-----";
                writer.write(publicStr);
            }
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException |
                 UnrecoverableKeyException e) {
            throw new RuntimeException(e);
        }


    }

}
