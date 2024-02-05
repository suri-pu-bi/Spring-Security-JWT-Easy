package com.security.exercise.SpringSecurityJWTEasy.service;

import com.security.exercise.SpringSecurityJWTEasy.dto.CustomUserDetails;
import com.security.exercise.SpringSecurityJWTEasy.entity.UserEntity;
import com.security.exercise.SpringSecurityJWTEasy.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        // DB에서 조회
        UserEntity userData = userRepository.findByUsername(username);

        if (userData != null) {

            // UserDetails에 담아서 return하면 AutneticationManager가 검증
            return new CustomUserDetails(userData);
        }

        return null;
    }
}
