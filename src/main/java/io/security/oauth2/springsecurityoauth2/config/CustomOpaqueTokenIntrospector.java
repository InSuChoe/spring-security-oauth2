package io.security.oauth2.springsecurityoauth2.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames;
import org.springframework.security.oauth2.server.resource.introspection.NimbusOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

public class CustomOpaqueTokenIntrospector implements OpaqueTokenIntrospector {
    @Autowired
    private OAuth2ResourceServerProperties properties;
    private  OpaqueTokenIntrospector delegate;

    public CustomOpaqueTokenIntrospector(OAuth2ResourceServerProperties properties)
    {
        OAuth2ResourceServerProperties.Opaquetoken opaquetoken = properties.getOpaquetoken();
        delegate = new NimbusOpaqueTokenIntrospector(
                opaquetoken.getIntrospectionUri(),
                opaquetoken.getClientId(),
                opaquetoken.getClientSecret());
    }

    @Override
    public OAuth2AuthenticatedPrincipal introspect(String token) {
        OAuth2AuthenticatedPrincipal principal =
                delegate.introspect(token);

        return new DefaultOAuth2AuthenticatedPrincipal(
                principal.getName(),
                principal.getAttributes(),
                extractAuthorities(principal));

    }

    public Collection<GrantedAuthority> extractAuthorities(OAuth2AuthenticatedPrincipal principal) {
        List<String> scopes =  principal.getAttribute(OAuth2TokenIntrospectionClaimNames.SCOPE);
        List<GrantedAuthority> authories = scopes.stream().map(scope -> "ROLE_" + scope.toUpperCase())
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
        return authories;
    }
}
