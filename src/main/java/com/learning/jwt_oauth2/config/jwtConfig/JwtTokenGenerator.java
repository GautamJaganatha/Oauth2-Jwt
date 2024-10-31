package com.learning.jwt_oauth2.config.jwtConfig;

import com.learning.jwt_oauth2.config.userConfig.UserInfoConfig;
import com.learning.jwt_oauth2.dto.AuthRequestDto;
import com.learning.jwt_oauth2.model.UserInfoEntity;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class JwtTokenGenerator {


    private final JwtEncoder jwtEncoder;


    public String generateAccessToken(Authentication authentication) {

        log.info("[JwtTokenGenerator:generateAccessToken] Token Creation Started for:{}", authentication.getName());

        String roles = getRolesOfUser(authentication);

        String permissions = getPermissionsFromRoles(roles);

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("gautam")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plus(15 , ChronoUnit.MINUTES))
                .subject(authentication.getName())
                .claim("scope", permissions)
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }


    private static String getRolesOfUser(Authentication authentication) {
        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(" "));
    }

    private String getPermissionsFromRoles(String roles) {
        Set<String> permissions = new HashSet<>();

        if (roles.contains("ADMIN")) {
            permissions.addAll(List.of("READ", "WRITE", "DELETE"));
        }
        if (roles.contains("CANDIDATE")) {
            permissions.add("READ");
        }
        if (roles.contains("MARKETING_MEMBER")) {
            permissions.add("READ");
        }

        return String.join(" ", permissions);
    }



    public String generateAccessToken2(UserInfoEntity userInfoEntity) {

        log.info("[JwtTokenGenerator:generateAccessToken] Token Creation Started for:{}", userInfoEntity.getUserName());

        UserInfoConfig userInfoConfig = new UserInfoConfig(userInfoEntity);
        String roles = getRolesOfUser2(userInfoConfig);

        String permissions = getPermissionsFromRoles(roles);

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("gautam")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plus(15 , ChronoUnit.MINUTES))
                .subject(userInfoEntity.getUserName())
                .claim("scope", permissions)
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }


    private static String getRolesOfUser2(UserInfoConfig userInfoConfig) {
        return userInfoConfig.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(" "));
    }

}

