package com.learning.jwt_oauth2.dto;

import lombok.Data;

@Data
public class AuthRequestDto {
    private String emailId;
    private String password;
}
