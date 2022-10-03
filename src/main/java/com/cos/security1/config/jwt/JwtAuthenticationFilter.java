package com.cos.security1.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.model.NewUser;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Date;

//스프링 시큐리티에 UsernamePasswordAuthenticationFilter가 있음
// /login 요청해서 username, password 전송하면(post)
// UsernamePasswordAuthenticationFilter가 동작을함
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    // /login 요청을 하면 로그인 시도를 위해 실행되는 함수
    // id와 pw가 맞는지 확인을 하면 된다
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter : 로그인 시도중");

        //1. username, password 받기
        //2. 정상인지 로그인 시도 해보기 authenticationManager로 로그인 시도를 하면
        // PrincipalDetailsService가 호출 loadUserByUsername 함수 자동 실행
        //3. PrincipalDetails를 세션에 담고 (권한 관리를 위해서)
        //4. JWT토큰을 만들어서 응답해주면 됨

        ObjectMapper om = new ObjectMapper();
        NewUser newUser = null;
        try {
            newUser = om.readValue(request.getInputStream(), NewUser.class);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        System.out.println("newUser = " + newUser);

        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(newUser.getUsername(), newUser.getPassword());

        //PrincipalDetailsService의 loadUserByUsername() 함수가 실행된 후 정상이면 authentication이 리턴됨
        //DB에 있는 username과 password가 일치
        Authentication authentication = authenticationManager.authenticate(authenticationToken);

        //로그인이 되었다는 뜻
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        System.out.println("principalDetails.getNewUser().getUsername() = " + principalDetails.getNewUser().getUsername());

        return authentication; //세션 저장됨(return 해주는 이유는 권한 관리를 security가 대신 해주기 때문에 편하려고 하는것)

//        try {
//            BufferedReader br = request.getReader();
//            String input = null;
//            while((input = br.readLine()) != null) {
//                System.out.println(input);
//            }
//        } catch (Exception e) {
//            throw new RuntimeException(e);
//        }
//
//        return null;
    }

    //attemptAuthentication 실행 후 인증이 정상적으로 되었으면 successfulAuthentication 함수가 실행됨
    //JWT 토큰을 만들어서 request요청한 사용자에게 JWT토큰을 response해주면 됨
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("successfulAuthentication 실행됨");
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        String jwtToken = JWT.create()
                .withSubject("cos토큰")
                .withExpiresAt(new Date(System.currentTimeMillis() + (60000 * 10)))
                .withClaim("id", principalDetails.getNewUser().getId())
                .withClaim("username", principalDetails.getNewUser().getUsername())
                .sign(Algorithm.HMAC512("cos"));

        response.addHeader("Authorization", "Bearer " + jwtToken);
    }
}
