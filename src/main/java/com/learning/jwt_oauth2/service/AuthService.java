package com.learning.jwt_oauth2.service;

import com.learning.jwt_oauth2.config.jwtConfig.JwtTokenGenerator;
import com.learning.jwt_oauth2.dto.AuthRequestDto;
import com.learning.jwt_oauth2.dto.AuthResponseDto;
import com.learning.jwt_oauth2.enums.Roles;
import com.learning.jwt_oauth2.repository.UserInfoRepo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final UserInfoRepo userInfoRepo;
    private final JwtTokenGenerator jwtTokenGenerator;



    public Object getJwtTokensAfterAuthentication2(AuthRequestDto authRequestDto) {
        try {
            var userInfoEntity = userInfoRepo.findByEmailId(authRequestDto.getEmailId())
                    .orElseThrow(()->{
                        log.error("[AuthService:userSignInAuth] User :{} not found ",authRequestDto.getEmailId());
                        return new ResponseStatusException(HttpStatus.NOT_FOUND, "USER NOT FOUND ");
                    });
            String accessToken = jwtTokenGenerator.generateAccessToken2(userInfoEntity);

            log.info("[AuthService:userSignInAuth] Access token for user : {}, has been generated",userInfoEntity.getUserName()+" at time "+ Instant.now());
            return  AuthResponseDto.builder()
                    .accessToken(accessToken)
                    .accessTokenExpiry(String.valueOf(15 * 60)+" secs")
                    .userName(userInfoEntity.getUserName())
                    .userRole(String.valueOf(userInfoEntity.getRoles()))
                    .tokenType(Roles.TokenType.Bearer)
                    .build();


        }catch (Exception e){
            log.error("[AuthService:userSignInAuth]Exception while authenticating the user due to :"+e.getMessage());
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,"Please Try Again");
        }
    }


    // Same method for verification
//    public Object getJwtTokensAfterAuthentication(Authentication authentication) {
//        try {
//            var userInfoEntity = userInfoRepo.findByEmailId(authentication.getName())
//                    .orElseThrow(()->{
//                        log.error("[AuthService:userSignInAuth] User :{} not found ",authentication.getName());
//                        return new ResponseStatusException(HttpStatus.NOT_FOUND, "USER NOT FOUND ");
//                    });
//            String accessToken = jwtTokenGenerator.generateAccessToken(authentication);
//
//            log.info("[AuthService:userSignInAuth] Access token for user:{}, has been generated",userInfoEntity.getUserName());
//            return  AuthResponseDto.builder()
//                    .accessToken(accessToken)
//                    .accessTokenExpiry(String.valueOf(15 * 60))
//                    .userName(userInfoEntity.getUserName())
//                    .tokenType(TokenType.Bearer)
//                    .build();
//
//
//        }catch (Exception e){
//            log.error("[AuthService:userSignInAuth]Exception while authenticating the user due to :"+e.getMessage());
//            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,"Please Try Again");
//        }
//    }

}
