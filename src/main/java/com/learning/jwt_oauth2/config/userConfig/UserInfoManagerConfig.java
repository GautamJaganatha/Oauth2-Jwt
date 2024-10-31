package com.learning.jwt_oauth2.config.userConfig;

import com.learning.jwt_oauth2.repository.UserInfoRepo;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserInfoManagerConfig implements UserDetailsService {

    private final UserInfoRepo userInfoRepo;

    @Override
    public UserDetails loadUserByUsername(String emailId) throws UsernameNotFoundException {
        return userInfoRepo
                .findByEmailId(emailId)
                .map(UserInfoConfig::new)
                .orElseThrow(()-> new UsernameNotFoundException("User with emailId: "+emailId+" not found"));
    }


}
