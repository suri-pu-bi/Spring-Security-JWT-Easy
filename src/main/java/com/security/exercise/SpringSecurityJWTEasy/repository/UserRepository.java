package com.security.exercise.SpringSecurityJWTEasy.repository;

import com.security.exercise.SpringSecurityJWTEasy.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserEntity, Integer> {
    Boolean existsByUsername (String username);
}
