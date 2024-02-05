package com.security.exercise.SpringSecurityJWTEasy.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class CorsMvcConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry corsRegistry) {

        // 모든 컨트롤러 경로에 대해서 프론트에서 요청이 오는 주소를 넣어주기
        corsRegistry.addMapping("/**")
                .allowedOrigins("http://localhost:3000");
    }
}
