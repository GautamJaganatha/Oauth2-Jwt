package com.learning.jwt_oauth2.repository;

import com.learning.jwt_oauth2.model.UserInfoEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserInfoRepo extends JpaRepository<UserInfoEntity, Long> {

    Optional<UserInfoEntity> findByEmailId(String emailId);

    UserInfoEntity findByUserName(String userName);
}
