package com.learning.jwt_oauth2.dto;

import com.learning.jwt_oauth2.enums.Roles;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SignUpDto {
    private Long id;
    private String userName;
    private String emailId;
    private String password;
    private String mobileNo;
    private Roles roles;
}
