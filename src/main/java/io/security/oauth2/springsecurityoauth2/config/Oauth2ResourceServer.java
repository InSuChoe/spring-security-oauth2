package io.security.oauth2.springsecurityoauth2.config;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import io.security.oauth2.springsecurityoauth2.filter.authentication.JwtAuthenticationFilter;
import io.security.oauth2.springsecurityoauth2.filter.authorization.JwtAuthorizationMacFilter;
import io.security.oauth2.springsecurityoauth2.filter.authorization.JwtAuthorizationRsaFilter;
import io.security.oauth2.springsecurityoauth2.filter.authorization.JwtAuthorizationRsaPublicKeyFilter;
import io.security.oauth2.springsecurityoauth2.signature.RSAPublicSecuritySigner;
import io.security.oauth2.springsecurityoauth2.signature.RSASecuritySigner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.security.interfaces.RSAPublicKey;

@Configuration
public class Oauth2ResourceServerConfig {


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {

        httpSecurity.csrf().disable();
        httpSecurity.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        httpSecurity.authorizeRequests(req -> req.antMatchers("/").permitAll()
                .anyRequest().authenticated());
        httpSecurity.userDetailsService(userDetailsService());
        httpSecurity.addFilterBefore(jwtAuthenticationFilter(null, null), UsernamePasswordAuthenticationFilter.class);
        httpSecurity.addFilterBefore(jwtAuthorizationRsaPublicKeyFilter(null),UsernamePasswordAuthenticationFilter.class);
        return httpSecurity.build();
    }
@Bean public JwtAuthorizationRsaPublicKeyFilter jwtAuthorizationRsaPublicKeyFilter(JwtDecoder jwtDecoder) throws JOSEException {
    return new JwtAuthorizationRsaPublicKeyFilter(jwtDecoder);
}
//    @Bean
//    public JwtAuthorizationRsaFilter jwtAuthorizationRsaFilter(RSAKey rsaKey) throws JOSEException {
//        return new JwtAuthorizationRsaFilter(new RSASSAVerifier(rsaKey.toRSAPublicKey()));
//    }


//    @Bean
//    public JwtAuthorizationMacFilter jwtAuthorizationMacFilter(OctetSequenceKey octetSequenceKey) throws JOSEException {
//        return new JwtAuthorizationMacFilter(new MACVerifier(octetSequenceKey.toSecretKey()));
//    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter(RSAPublicSecuritySigner rsaPublicSecuritySigner, RSAKey rsaKey) throws Exception {
        JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(rsaPublicSecuritySigner, rsaKey);
        jwtAuthenticationFilter.setAuthenticationManager(authenticationManager(null));
        return jwtAuthenticationFilter;

    }


    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.withUsername("user")
                .password("1234")
                .authorities("ROLE_USER")
                .build();
        return new InMemoryUserDetailsManager(user);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }
}
