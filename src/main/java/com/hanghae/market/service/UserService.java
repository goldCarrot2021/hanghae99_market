package com.hanghae.market.service;


import com.hanghae.market.dto.SignupReqeustDto;
import com.hanghae.market.repository.UserRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.validation.Errors;
import org.springframework.validation.FieldError;

import java.util.HashMap;
import java.util.Map;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public UserService(UserRepository userRepository,BCryptPasswordEncoder bCryptPasswordEncoder ) {
        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }


    // 회원가입 유효성 체크 시 뜨는 에러를 map에 넣어 반환
    public Map<String,String> validateHandling(Errors errors){
        Map<String,String> validatorResult = new HashMap<>();
        for(FieldError error : errors.getFieldErrors()){
            String validKeyName = error.getField();
            validatorResult.put(validKeyName,error.getDefaultMessage());
        }
        return validatorResult;
    }

    public String signup(SignupReqeustDto reqeustDto){

        /* 비밀번호 암호화 */
        String encodPassword = bCryptPasswordEncoder.encode(reqeustDto.getPassword());
        reqeustDto.setPassword(encodPassword);

        userRepository.save(reqeustDto.toEntity());
        return "true";
    }

    public String usernameCheck(String username){
        boolean result = userRepository.existsByUsername(username);

        if (!result) {
            return "true";
        }else{
            return "false";
        }

    }

    public String emailCheck(String email){
        boolean result =  userRepository.existsByEmail(email);
        if (!result) {
            return "true";
        }else{
            return "false";
        }
    }



}
