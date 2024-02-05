package com.security.exercise.SpringSecurityJWTEasy.controller;

import com.security.exercise.SpringSecurityJWTEasy.service.JoinService;
import com.security.exercise.SpringSecurityJWTEasy.dto.JoinDTO;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@ResponseBody
@Slf4j
public class JoinController {

    private final JoinService joinService;

    private JoinController(JoinService joinService){
        this.joinService = joinService;
    }

    @PostMapping("/join")
    public String joinProcess(JoinDTO joinDTO){ // postman에서 form-data 방식으로 값 넘겨줌
        log.info(joinDTO.toString());
        joinService.joinProcess(joinDTO);

        return "ok";
    }
}
