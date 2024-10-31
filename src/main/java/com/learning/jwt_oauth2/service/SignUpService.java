package com.learning.jwt_oauth2.service;

import com.learning.jwt_oauth2.dto.SignUpDto;
import com.learning.jwt_oauth2.model.UserInfoEntity;
import com.learning.jwt_oauth2.repository.UserInfoRepo;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class SignUpService {

    private final UserInfoRepo userInfoRepo;
    private final PasswordEncoder passwordEncoder;

    public SignUpService(UserInfoRepo userInfoRepo, PasswordEncoder passwordEncoder) {
        this.userInfoRepo = userInfoRepo;
        this.passwordEncoder = passwordEncoder;
    }

    public SignUpDto signUp(SignUpDto signUpDto){
        UserInfoEntity createUser = new UserInfoEntity();

        createUser.setUserName(signUpDto.getUserName());
        createUser.setEmailId(signUpDto.getEmailId());
        createUser.setPassword(passwordEncoder.encode(signUpDto.getPassword()));
        createUser.setRoles(signUpDto.getRoles());
        createUser.setMobileNumber(signUpDto.getMobileNo());

        userInfoRepo.save(createUser);

        return createUser.getSignUpDto();

    }
}
