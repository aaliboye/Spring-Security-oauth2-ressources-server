package com.example.SpringSecurity.login.controller;

import java.util.Map;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestRestAPI {

    @GetMapping("/datatest")
    @PreAuthorize("hasAuthority('SCOPE_ADMIN')")
    public Map<String, Object> datatest(Authentication authentication){
        return Map.of(
            "message", "data test",
            "username", authentication.getName(),
            "authorities", authentication.getAuthorities()
        );
    }

    @PostMapping("/savedata")
    @PreAuthorize("hasAuthority('SCOPE_USER')")
    public Map<String, String> saveData(String data){
        return Map.of("data", data);
    }

    
}
