package io.security.springsecuritymaster;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;

@EnableWebSecurity
@Configuration
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .formLogin(Customizer.withDefaults())
                .rememberMe(rememberMe -> rememberMe
//                        .alwaysRemember(true)
                        .tokenValiditySeconds(3600)
                        .userDetailsService(userDetailsService())
                        .rememberMeParameter("remember")
                        .rememberMeCookieName("remember")
                        .key("security")
                );
        return http.build();

        // httpBasic()
//        http
//                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
////                .httpBasic(Customizer.withDefaults());
//                .httpBasic(basic -> basic.authenticationEntryPoint(new CustomAuthenticationEntryPoint(){}));
//        return http.build();


        // formLogin()
//        http
//                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())   // 어떠한 경우에도 인증을 받아야 함.
////                .formLogin(Customizer.withDefaults());
//                .formLogin(form -> form                                             // 인증을 받지 못했기에 로그인 페이지로 이동
////                        .loginPage("/loginPage")                                                               // 커스텀한 로그인 페이지 주소. 비활성화시 기본 제공되는 페이지 사용.
//                        .loginProcessingUrl("/loginProc")
//                        .defaultSuccessUrl("/", false)                                    // 로그인 성공 후 ture -> 설정한 url로, false -> 인증에 막혀 접근하지 못했던 경로로 이동.
//                        .failureUrl("/failed")
//                        .usernameParameter("userId")
//                        .passwordParameter("passwd")
////                        .successHandler((request, response, authentication) -> {                              // 위에서 설정한 내용보다 직접 오버라이딩한 핸들러가 우선 적용됨.
////                            System.out.println("authentication : " + authentication);
////                            response.sendRedirect("/home");
////                        })
////                        .failureHandler((request, response, exception) -> {
////                            System.out.println("exception : " + exception);
////                            response.sendRedirect("/login");
////                        })
//                        .permitAll()
//                );
//        return http.build();
    }

    // Config file (application.yml)과 중복일 경우 코드설정이 우선
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user1 = User.withUsername("user1")
                .password("{noop}1111")
                .roles("USER").build();

//        UserDetails user2 = User.withUsername("user2")
//                .password("{noop}1111")
//                .roles("USER").build();
//
//        UserDetails user3 = User.withUsername("user3")
//                .password("{noop}1111")
//                .roles("USER").build();
//
//        return new InMemoryUserDetailsManager(user1, user2, user3);

        return new InMemoryUserDetailsManager(user1);
    }
}
