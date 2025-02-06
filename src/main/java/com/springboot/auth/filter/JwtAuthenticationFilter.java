package com.springboot.auth.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.springboot.auth.dto.LoginDto;
import com.springboot.auth.jwt.JwtTokenizer;
import com.springboot.member.entity.Member;
import lombok.SneakyThrows;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

//엔트리 포인트 진입점을 직접 만듬
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;
    private final JwtTokenizer jwtTokenizer;

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager,
                                   JwtTokenizer jwtTokenizer) {
        this.authenticationManager = authenticationManager;
        this.jwtTokenizer = jwtTokenizer;
    }

    @SneakyThrows
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response){
        //dto로 받아오는것 JSON이기에 역직렬화 해주어야 한다.
        //여기는 spring이 아닌 서블릿의 영역이라 직접 매핑 해주어야 한다.
        ObjectMapper objectMapper = new ObjectMapper();

        //JSON 형태의 값(KEY:VALUE)를 DTO로 변환
        LoginDto loginDto = objectMapper.readValue(request.getInputStream(), LoginDto.class);

        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword());

        //authenticationManager한테 넘겨준다
        return authenticationManager.authenticate(authenticationToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authResult){
        Member member = (Member) authResult.getPrincipal();
        String accessToken = delegateAccessToken(member);
        String refreshToken = delegateRefreshToken(member);

        //액세스 토큰과 리프래쉬 토큰을 헤더로 보낸다.
        response.setHeader("Authorization", "Bearer " + accessToken);
        response.setHeader("Refresh", refreshToken);
    }

    //해당 사용자의 액세스 토큰을 만드는 메서드
    private String delegateAccessToken(Member member){
        Map<String, Object> claims = new HashMap<>();
        claims.put("username", member.getEmail());
        claims.put("roles", member.getRoles());

        String subject = member.getEmail();
        //만료기간 가져옴
        Date expiraiton = jwtTokenizer.getTokenExpiration(jwtTokenizer.getAccessTokenExpirationMinutes());
        String base64EncodedSecretKey = jwtTokenizer.encodeBase64SecretKey(jwtTokenizer.getSecretKey());

        String accessToken = jwtTokenizer.generateAccessToken(claims, subject, expiraiton,base64EncodedSecretKey);
        return accessToken;
    }

    private String delegateRefreshToken(Member member){
        String subject = member.getEmail();
        Date expiraiton = jwtTokenizer.getTokenExpiration(jwtTokenizer.getRefreshTokenExpirationMinutes());
        String base64EncodedSecretKey = jwtTokenizer.encodeBase64SecretKey(jwtTokenizer.getSecretKey());

        String refreshToken = jwtTokenizer.generateRefreshToken(subject, expiraiton, base64EncodedSecretKey);
        return refreshToken;
    }
}
