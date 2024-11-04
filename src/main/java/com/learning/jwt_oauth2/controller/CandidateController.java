package com.learning.jwt_oauth2.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/candidate")
public class CandidateController {
    @GetMapping("/WELCOME")
    public ResponseEntity<String> getMessage(){
        return ResponseEntity.ok("Welcome message its successful");
    }
}
