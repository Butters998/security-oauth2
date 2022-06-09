package com.faferek.securityoauth2;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @GetMapping("/for-all")
    public String getForAll(){
        return "for all";
    }

    @GetMapping("/bye")
    public String getBye(){
        return "Bye";
    }

    @GetMapping("/for-user")
    public String getForUser(){
        return "user";
    }

    @GetMapping("/for-admin")
    public String getForAdmin(){
        return "admin";
    }
}
