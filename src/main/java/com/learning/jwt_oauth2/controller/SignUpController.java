package com.learning.jwt_oauth2.controller;

import com.learning.jwt_oauth2.dto.SignUpDto;
import com.learning.jwt_oauth2.model.UserInfoEntity;
import com.learning.jwt_oauth2.service.SignUpService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/")
public class SignUpController {

    private final SignUpService signUpService;

    public SignUpController(SignUpService signUpService) {
        this.signUpService = signUpService;
    }


    @PostMapping("/signUp")
    public ResponseEntity<?> singUp(@RequestBody SignUpDto signUpDto){
        return ResponseEntity.ok(signUpService.signUp(signUpDto));
    }
}
