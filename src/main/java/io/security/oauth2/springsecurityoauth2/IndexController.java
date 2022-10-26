package io.security.oauth2.springsecurityoauth2;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IndexController {
    @GetMapping("/index")
    public String index(Authentication authentication){
        return "index";
    }
    @GetMapping("/api/user")
    public Authentication apiUser(Authentication authentication)
    {
        return authentication;
    }
}
