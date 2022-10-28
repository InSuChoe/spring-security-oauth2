package io.security.oauth2.springsecurityoauth2.controller;

import io.security.oauth2.springsecurityoauth2.OpaqueDto;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class IndexController {
    @GetMapping("/")
    public Authentication index(Authentication authentication,
                                @AuthenticationPrincipal OAuth2AuthenticatedPrincipal oAuth2AuthenticatedPrincipal) {
        BearerTokenAuthentication authenticationToken=
                (BearerTokenAuthentication) authentication;

        Map<String, Object> tokenAttributes=
                authenticationToken.getTokenAttributes();

        OpaqueDto opaqueDto = new OpaqueDto();
        boolean active = (boolean) tokenAttributes.get("active");
        opaqueDto.setActive(active);
        opaqueDto.setAuthentication(authentication);
        opaqueDto.setPrincipal(oAuth2AuthenticatedPrincipal);
        return authentication;
    }

    @GetMapping("/api/user")
    public Authentication apiUser(Authentication authentication) {
        return authentication;
    }
}
