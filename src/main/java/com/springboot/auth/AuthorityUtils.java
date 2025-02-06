package com.springboot.auth;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.Collectors;

@Component
public class AuthorityUtils {
    //application.yml에 추가한 프로퍼티를 가져오는 표현식 ( 프로퍼티의 값을 가져와서 쓸수있음 )
    @Value("${mail.address.admin}")
    private String adminMailAddress;

    //스프링 시큐리티에서 지원하는 AuthorityUtils 클래스로 사용 권한 목록을 객체로 미리 생성
    private final List<GrantedAuthority> ADMIN_ROLES = org.springframework.security.core.authority.AuthorityUtils.createAuthorityList("ROLE_ADMIN","ROLE_USER");

    //관리자 권한의 경우 일반 사용자의 권한까지 주지만, 일반 사용자는 일반사용자 권한만 객체로 미리 생성
    private final List<GrantedAuthority> USER_ROLES = org.springframework.security.core.authority.AuthorityUtils.createAuthorityList("ROLE_USER");

    //DB에 권한정보를 저장하기 위한 필드
    private final List<String> ADMIN_ROLES_STRING = List.of("ADMIN","USER");
    private final List<String> USER_ROLES_STRING = List.of("USER");

    //DB 저장용으로 변경
    public List<String> createAuthorities(String email){
        //만약 이메일이 yml에서 가져온 관리자 이메일주소가 동일하다면 관리자 권한을 리턴
        if(email.equals(adminMailAddress)){
            return ADMIN_ROLES_STRING;
        }
        //다르다면 사용자 권한을 리턴한다.
        return USER_ROLES_STRING;
    }

    //데이터베이스에 저장된 Role목록을 가져와 권한 목록(정보)을 생성한다
    public List<GrantedAuthority> createAuthorities(List<String> roles){
        List<GrantedAuthority> authorities = roles.stream()
                //SimpleGrantedAuthority 클래스는 권한을 생성해주는 클래스
                //무조건 객체 생성시 파라밑로 넘기는값은 ROLE_이 붙어야한다.
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .collect(Collectors.toList());
        return authorities;
    }
}
