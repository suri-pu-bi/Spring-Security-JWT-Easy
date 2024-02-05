package com.security.exercise.SpringSecurityJWTEasy.config;

import com.security.exercise.SpringSecurityJWTEasy.jwt.JwtFilter;
import com.security.exercise.SpringSecurityJWTEasy.jwt.JwtUtil;
import com.security.exercise.SpringSecurityJWTEasy.jwt.LoginFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity // Security를 위한 Config
@RequiredArgsConstructor
public class SecurityConfig {

    //AuthenticationManager가 인자로 받을 AuthenticationConfiguraion 객체 생성자 주입
    private final AuthenticationConfiguration authenticationConfiguration;

    private final JwtUtil jwtUtil;

    //AuthenticationManager Bean 등록
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

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

        // 필터 추가
        // addFilterAt : 원하는 자리에 등록
        // addFilterBefore : 특정 필터 전에 등록, addFilterAfter : 특정 필터 후에 등록
        http
                .addFilterBefore(new JwtFilter(jwtUtil), LoginFilter.class);

        // LoginFilter()는 인자를 받음 : AuthenticationManager() 메소드에 authenticationConfiguration 객체를 넣어야 함
        // 따라서 등록 필요
        http
                .addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration), jwtUtil), UsernamePasswordAuthenticationFilter.class);

        // 가장 중요) JWT 방식에서는 항상 세션을 STATELESS로 설정해줘야함
        http
                .sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));


        return http.build();



    }
}
