package com.faferek.securityoauth2;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Collections;

@Configuration
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    public PasswordEncoder getBcrytpPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        User user = new User("jan", getBcrytpPasswordEncoder().encode("jan123"),
                Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")));
        User admin = new User("admin", getBcrytpPasswordEncoder().encode("admin123"),
                Collections.singleton(new SimpleGrantedAuthority("ROLE_ADMIN")));

        auth.inMemoryAuthentication().withUser(user);
        auth.inMemoryAuthentication().withUser(admin);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/for-user").hasAnyRole("USER", "ADMIN")
                .antMatchers("/for-admin").hasAuthority("ROLE_ADMIN")
                .and()
                .formLogin().permitAll()
                .and()
                .logout().logoutUrl("/bye");
    }
}
