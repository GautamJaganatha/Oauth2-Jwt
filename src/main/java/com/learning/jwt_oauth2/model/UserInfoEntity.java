package com.learning.jwt_oauth2.model;

import com.learning.jwt_oauth2.dto.SignUpDto;
import com.learning.jwt_oauth2.enums.Roles;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;


@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "USER_INFO")
public class UserInfoEntity  {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "USER_NAME")
    private String userName;

    @Column(nullable = false, name = "EMAIL_ID", unique = true)
    private String emailId;

    @Column(nullable = false, name = "PASSWORD")
    private String password;

    @Column(name = "MOBILE_NUMBER")
    private String mobileNumber;

    @Column(nullable = false, name = "ROLES")
    @Enumerated(EnumType.STRING)
    private Roles roles;


    public SignUpDto getSignUpDto(){
        SignUpDto sign = new SignUpDto();
        sign.setId(id);
        sign.setUserName(userName);
        sign.setEmailId(emailId);
        sign.setMobileNo(mobileNumber);
        sign.setRoles(roles);

        return sign;
    }


}
