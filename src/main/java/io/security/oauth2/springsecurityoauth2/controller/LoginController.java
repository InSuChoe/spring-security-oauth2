package io.security.oauth2.springsecurityoauth2.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoginController {
    @GetMapping("/loginPage")
    public String loginPage()
    {
        return "loginPage";
    }
}
