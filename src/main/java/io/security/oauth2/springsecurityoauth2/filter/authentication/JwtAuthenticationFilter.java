package io.security.oauth2.springsecurityoauth2.filter.authentication;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import io.security.oauth2.springsecurityoauth2.dto.LoginDto;
import io.security.oauth2.springsecurityoauth2.signature.SecuritySigner;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private SecuritySigner securitySigner;
    private JWK jwk;

    public JwtAuthenticationFilter(SecuritySigner securitySigner, JWK jwk) {
        this.securitySigner = securitySigner;

        this.jwk =jwk;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        ObjectMapper objectMapper = new ObjectMapper();
        LoginDto loginDto = null;
        try {
            loginDto=objectMapper.readValue(request.getInputStream(),LoginDto.class);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        UsernamePasswordAuthenticationToken authenticationToken
                = new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword());

        return getAuthenticationManager().authenticate(authenticationToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        String jwtToken;
        User user = (User) authResult.getPrincipal();
        try {
             jwtToken = securitySigner.getJwtToken(user, jwk);
             response.addHeader("Authorization", "Bearer "+jwtToken);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }

    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        System.out.println("ASD");
        super.unsuccessfulAuthentication(request, response, failed);
    }
}
