package com.learning.jwt_oauth2.service;

import com.learning.jwt_oauth2.config.jwtConfig.JwtTokenGenerator;
import com.learning.jwt_oauth2.dto.AuthResponseDto;
import com.learning.jwt_oauth2.dto.TokenType;
import com.learning.jwt_oauth2.repository.UserInfoRepo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final UserInfoRepo userInfoRepo;
    private final JwtTokenGenerator jwtTokenGenerator;

    public Object getJwtTokensAfterAuthentication(Authentication authentication) {
        try {
            var userInfoEntity = userInfoRepo.findByEmailId(authentication.getName())
                    .orElseThrow(()->{
                        log.error("[AuthService:userSignInAuth] User :{} not found ",authentication.getName());
                        return new ResponseStatusException(HttpStatus.NOT_FOUND, "USER NOT FOUND ");
                    });
            String accessToken = jwtTokenGenerator.generateAccessToken(authentication);

            log.info("[AuthService:userSignInAuth] Access token for user:{}, has been generated",userInfoEntity.getUserName());
            return  AuthResponseDto.builder()
                    .accessToken(accessToken)
                    .accessTokenExpiry(15 * 60)
                    .userName(userInfoEntity.getUserName())
                    .tokenType(TokenType.Bearer)
                    .build();


        }catch (Exception e){
            log.error("[AuthService:userSignInAuth]Exception while authenticating the user due to :"+e.getMessage());
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,"Please Try Again");
        }
    }
}
