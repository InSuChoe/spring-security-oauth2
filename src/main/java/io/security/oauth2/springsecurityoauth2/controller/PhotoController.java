package io.security.oauth2.springsecurityoauth2.controller;

import io.security.oauth2.springsecurityoauth2.config.Photo;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class PhotoController {
    @GetMapping("/photos/1")
    public Photo photo1()
    {
        return Photo.builder()
                .photoId("1")
                .photoTitle("Photo 1 title")
                .photoDescription("Photo is nice")
                .userId("user1")
                .build();
    }
    @GetMapping("/photos/2")
    public Photo photo2()
    {
        return Photo.builder()
                .photoId("2")
                .photoTitle("Photo 2 title")
                .photoDescription("Photo is beauty")
                .userId("user2")
                .build();
    }
}
