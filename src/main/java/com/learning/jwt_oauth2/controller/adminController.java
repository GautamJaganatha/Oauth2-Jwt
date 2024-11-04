package com.learning.jwt_oauth2.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/admin/")
public class adminController {

//    @PreAuthorize("hasAuthority('SCOPE_READ')")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @GetMapping("Welcome")
    public ResponseEntity<String> getMessage(){
        return ResponseEntity.ok("Welcome message its Successful");
    }


    @PostMapping("postWelcome")
    public ResponseEntity<?> addSomething(){
        return ResponseEntity.ok("Welcome message its Successful");
    }
}
