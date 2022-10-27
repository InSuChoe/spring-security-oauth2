package io.security.oauth2.springsecurityoauth2;

import org.junit.jupiter.api.Test;

public class JustTest {
    @Test
    public void testPath()
    {
        int i = "apiKey.jks".indexOf(".");
        System.out.println("apiKey.jks".substring(0, i ));
    }
    @Test
    public  void testHeader()
    {
        String s = "Bearer ASD";
        String bearer_ = s.replace("Bearer ", "");
        System.out.println("bearer_ = " + bearer_);

    }
}
