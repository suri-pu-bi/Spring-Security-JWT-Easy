package com.security.exercise.SpringSecurityJWTEasy.service;

import com.security.exercise.SpringSecurityJWTEasy.dto.JoinDTO;
import com.security.exercise.SpringSecurityJWTEasy.entity.UserEntity;
import com.security.exercise.SpringSecurityJWTEasy.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class JoinService {
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public UserEntity joinProcess(JoinDTO joinDTO){
        String username = joinDTO.getUsername();
        String password = joinDTO.getPassword();

        Boolean isExist = userRepository.existsByUsername(username);

        if (isExist) {
            return null; // 회원가입이 안됐다는 response 보내줄 수도 있음
        }

        UserEntity userEntity = UserEntity.builder()
                .username(username)
                .password(bCryptPasswordEncoder.encode(password))
                .role("ROLE_ADMIN") // 스프링 : 접두사를 가지고 그 뒤에 원하는 권한 입력
                .build();

        return userRepository.save(userEntity);



    }

}
