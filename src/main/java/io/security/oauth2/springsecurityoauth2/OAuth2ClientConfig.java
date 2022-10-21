package io.security.oauth2.springsecurityoauth2;

import org.springframework.beans.SimpleTypeConverter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ClientRegistrations;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

@EnableWebSecurity
public class OAuth2ClientConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeRequests(authRequest->authRequest.anyRequest().authenticated());
        http.oauth2Login(Customizer.withDefaults());
        http.logout().logoutSuccessHandler(oidcLogoutSuccessHandler())
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                .deleteCookies("JSESSIONID");
        return http.build();
    }

    @Autowired
    private ClientRegistrationRepository clientRegistrationRepository;
    private LogoutSuccessHandler oidcLogoutSuccessHandler() {
        OidcClientInitiatedLogoutSuccessHandler successHandler=new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
        successHandler.setPostLogoutRedirectUri("http://localhost:8081/login");
        return successHandler;
    }

//    @Bean
//    public ClientRegistrationRepository clientRegistrationRepository() {
//        return new InMemoryClientRegistrationRepository(keycloakClientRegistration());
//    }
//    private ClientRegistration keycloakClientRegistration() {
//        return ClientRegistrations.fromIssuerLocation("http://localhost:8080/realms/oauth2")
//                .registrationId("keycloak")
//                .clientId("oauth2-client-app")
//                .clientSecret("xpAtpy78LjFpB22GomZQeGawYNQKfl9o")
//                .redirectUri("http://localhost:8081/login/oauth2/code/keycloak")
                        //        .issuerUri()
//                .build();
//    }
}
