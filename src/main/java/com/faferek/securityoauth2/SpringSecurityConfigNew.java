package com.faferek.securityoauth2;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import java.util.Arrays;

@Configuration
public class SpringSecurityConfigNew {
    @Bean
    public PasswordEncoder getBcrytpPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public InMemoryUserDetailsManager get() {
        UserDetails user = User.withUsername("jan")
                .password(getBcrytpPasswordEncoder().encode("jan123"))
                .roles("USER")
                .build();
        UserDetails admin = User.withUsername("admin")
                .password(getBcrytpPasswordEncoder().encode("admin123"))
                .roles("ADMIN")
                .build();

        return new InMemoryUserDetailsManager(Arrays.asList(user, admin));
    }
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeRequests((autz) -> autz
                .antMatchers("/for-user").hasAnyRole("USER", "ADMIN")
                .antMatchers("/for-admin").hasAnyRole("ADMIN")
        )
                .formLogin((formLogin) -> formLogin.permitAll())
                .logout()
                .logoutSuccessUrl("/bye").permitAll();


                // .deleteCookies("Cookies")


        return http.build();
    }

}
