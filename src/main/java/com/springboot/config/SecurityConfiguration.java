package com.springboot.config;

import com.springboot.auth.filter.JwtAuthenticationFilter;
import com.springboot.auth.jwt.JwtTokenizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;


@Configuration
public class SecurityConfiguration {
    private final JwtTokenizer jwtTokenizer;

    public SecurityConfiguration(JwtTokenizer jwtTokenizer) {
        this.jwtTokenizer = jwtTokenizer;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception{
        httpSecurity
                .headers().frameOptions().sameOrigin()
                .and()
                //로컬에서만 사용하기에 csrf 공격보안을 끔
                .csrf().disable()
                //cors 설정
                //withDefaults는 기본설정을 한다는 것, 자동으로 만들어주진 않는다.
                .cors(Customizer.withDefaults())
                //formLogin 설정을 끈다.
                .formLogin().disable()
                .httpBasic().disable()
                //커스텀으로 만든
                .apply(new CustomFilterConfigurer())
                .and()
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().permitAll());

        return httpSecurity.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    //COSR 기본설정
    @Bean
    CorsConfigurationSource corsConfiguration(){
        CorsConfiguration configuration = new CorsConfiguration();
        //Origin 전체 허용
        configuration.setAllowedOrigins(Arrays.asList("*"));
        //Method는 GET,POST,PATCH,DELETE만 허용
        configuration.setAllowedMethods(List.of("GET","POST","PATCH","DELETE"));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }

    //우리가 만든 JwtAuthenticationFilter를 등록하기 위한 메서드
    //AbstractHttpConfigurer를 상속
    public class CustomFilterConfigurer extends AbstractHttpConfigurer<CustomFilterConfigurer, HttpSecurity>{
        @Override
        public void configure(HttpSecurity builder){
            //우리가 만든 필터를 등록하기 위해 AuthenticaitonManager를 등록한다.
            AuthenticationManager authenticationManager = builder.getSharedObject(AuthenticationManager.class);

            JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(authenticationManager, jwtTokenizer);
            //필터가 적용하기 위한 로그인 url를 변경한다.
            //만약 변경하지 않으면 디폴트로 url은 login
            jwtAuthenticationFilter.setFilterProcessesUrl("/v11/auth/login");

            //addFilter로 추가하면 빌더 내부에서 체인필터에 등록된다.
            builder.addFilter(jwtAuthenticationFilter);
        }
    }
}
