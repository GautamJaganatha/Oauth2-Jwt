package com.learning.jwt_oauth2.config.jwtConfig;

import com.learning.jwt_oauth2.config.RSAKeyRecord;
import com.learning.jwt_oauth2.dto.TokenType;
import com.learning.jwt_oauth2.model.UserInfoEntity;
import com.learning.jwt_oauth2.repository.UserInfoRepo;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

@RequiredArgsConstructor
@Slf4j
public class JwtAccessTokenFilter extends OncePerRequestFilter {

    private final RSAKeyRecord rsaKeyRecord;
    private final JwtTokenUtils jwtTokenUtils;
    private final UserInfoRepo userInfoRepo;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        try {
            log.info("[JwtAccessTokenFilter:doFilterInternal] :: Started ");

            log.info("[JwtAccessTokenFilter:doFilterInternal] Filtering the Http Request: {}", request.getRequestURI());

            final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

            if (authHeader == null || !authHeader.startsWith(TokenType.Bearer.name())) {
                filterChain.doFilter(request, response);
                return;
            }

            final String token = authHeader.substring(7);
            JwtDecoder jwtDecoder = NimbusJwtDecoder.withPublicKey(rsaKeyRecord.rsaPublicKey()).build();
            final Jwt jwtToken = jwtDecoder.decode(token);

            final String userName = jwtTokenUtils.getUserName(jwtToken);

            log.info("Username of token is : {}", userName);

//            UserInfoEntity user = userInfoRepo.findByUserName(userName);

            Optional<UserInfoEntity> user = userInfoRepo.findByEmailId(userName);

            if (user == null) {
                log.warn("User not found with username: {}", userName);
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "User not found");
                return;
            }

            if (!userName.isEmpty() && SecurityContextHolder.getContext().getAuthentication() == null) {
                log.info("Found user with emailId: {}", user.get().getEmailId());
                UserDetails userDetails = jwtTokenUtils.userDetails(user.get().getEmailId());

                if (jwtTokenUtils.isTokenValid(jwtToken, userDetails)) {
                    SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
                    UsernamePasswordAuthenticationToken createdToken = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );
                    createdToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    securityContext.setAuthentication(createdToken);
                    SecurityContextHolder.setContext(securityContext);
                }
            }

            log.info("[JwtAccessTokenFilter:doFilterInternal] Completed");
            filterChain.doFilter(request, response);
        } catch (JwtValidationException jwtValidationException) {
            log.error("[JwtAccessTokenFilter:doFilterInternal] JWT Validation Error: {}", jwtValidationException.getMessage());
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "JWT validation failed: " + jwtValidationException.getMessage());
        }
    }

}
