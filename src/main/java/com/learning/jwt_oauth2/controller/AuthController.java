package com.learning.jwt_oauth2.controller;

import com.learning.jwt_oauth2.dto.AuthRequestDto;
import com.learning.jwt_oauth2.service.AuthService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthService authService;

    private final AuthenticationManager authenticationManager;

//    @PostMapping("/sign-in")
//    public ResponseEntity<?> authentication(Authentication authentication){
//        return ResponseEntity.ok(authService.getJwtTokensAfterAuthentication(authentication));
//    }

    @PostMapping("/sign-in")
    public ResponseEntity<?> singIn(@RequestBody AuthRequestDto authRequestDto){
        log.info("Attempting to sign in user with email: {}", authRequestDto.getEmailId());
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authRequestDto.getEmailId(), authRequestDto.getPassword()));
            log.info("Authentication successful for user: {}", authRequestDto.getEmailId());
        } catch (BadCredentialsException e) {
            log.error("Authentication failed: {}", e.getMessage());
            throw new BadCredentialsException("Incorrect username or password");
        }
        return ResponseEntity.ok(authService.getJwtTokensAfterAuthentication2(authRequestDto));
    }
}
