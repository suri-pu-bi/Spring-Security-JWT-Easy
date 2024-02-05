package com.security.exercise.SpringSecurityJWTEasy.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity // Security를 위한 Config
public class SecurityConfig {

    // 비밀번호를 암호화시켜서 검증 수행
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{

        // csrf disable : 세션 방식에서는 세션이 고정되기때문에 csrf 공격을 방어해줘야함
        // token 방식에서는 세션을 STATELESS로 관리하므로 csrf 공격을 방어하지 않아도됨
        http
                .csrf((auth) -> auth.disable());

        // Form 로그인 방식 disable : api 방식을 사용할 것이기 때문
        http
                .formLogin((auth) -> auth.disable());

        // http basic 인증 방식 disable
        http
                .httpBasic((auth) -> auth.disable());

        // 경로별 인가 작업
        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/login", "/", "/join").permitAll()
                        // "ADMIN" 이라는 권한을 가진 사용자만 접근 가능
                        .requestMatchers("/admin").hasRole("ADMIN")
                        // 다른 요청에 대해서는 로그인한 사용자만 접근 가능
                        .anyRequest().authenticated());

        // 가장 중요) JWT 방식에서는 항상 세션을 STATELESS로 설정해줘야함
        http
                .sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));


        return http.build();



    }
}
