package io.security.oauth2.springsecurityoauth2.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.server.resource.introspection.NimbusOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class Oauth2ResourceServer {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.authorizeRequests(req -> req.anyRequest().authenticated());
        httpSecurity.oauth2ResourceServer(OAuth2ResourceServerConfigurer::opaqueToken);
        return httpSecurity.build();
    }
//    @Bean
//    public OpaqueTokenIntrospector opaqueTokenIntrospector
//            (OAuth2ResourceServerProperties properties)
//    {
//        OAuth2ResourceServerProperties.Opaquetoken opaquetoken =
//                properties.getOpaquetoken();
//
//        return new NimbusOpaqueTokenIntrospector
//                (opaquetoken.getIntrospectionUri(),
//                        opaquetoken.getClientId(),
//                        opaquetoken.getClientSecret());
//    }
    @Autowired
    private OAuth2ResourceServerProperties properties;
    @Bean
    public OpaqueTokenIntrospector opaqueTokenIntrospector()
    {
        return new CustomOpaqueTokenIntrospector(properties);
    }
}
