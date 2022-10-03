package com.cos.security1.controller;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.model.NewUser;
import com.cos.security1.repository.NewUserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("api/v1")
@RequiredArgsConstructor
public class RestApiController {
    private final NewUserRepository newUserRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @GetMapping("/home")
    public String home() {
        return "<h1>home</h1>";
    }

    @PostMapping("/token")
    public String token() {
        return "<h1>token</h1>";
    }

    @GetMapping("user")
    public String user(Authentication authentication) {
        PrincipalDetails principal = (PrincipalDetails) authentication.getPrincipal();
        System.out.println("principal : " + principal.getNewUser().getId());
        System.out.println("principal : " + principal.getNewUser().getUsername());
        System.out.println("principal : " + principal.getNewUser().getPassword());

        return "<h1>user</h1>";
    }

    @GetMapping("manager/reports")
    public String reports() {
        return "<h1>reports</h1>";
    }

    @GetMapping("admin/users")
    public List<NewUser> users() {
        return newUserRepository.findAll();
    }

    @PostMapping("join")
    public String join(@RequestBody NewUser newUser) {
        newUser.setPassword(bCryptPasswordEncoder.encode(newUser.getPassword()));
        newUser.setRoles("ROLE_USER");
        newUserRepository.save(newUser);

        return "회원가입완료";
    }
}
