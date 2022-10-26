package com.farrel.springsecurityjwt.security;

/*
 * authentication meaning who. Verifies who you are who you say you are.
 *
 * authorization meaning what they can access in the application, and
 * we're going to control that using the role. It will decides if you have
 * permission to access a resource.
 */

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor // I'm going to be doing some dependency injection, so we can use this annotation from lombok
/*
* to tell spring what we're trying to do, we need to override certain methods
* from the WebSecurityConfigurerAdapter, which is the main security class.
 */
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    /*
    * Because we have @RequiredArgsConstructor annotation from lombok.
    * The annotation is going to create a constructor for us on the fly
    * and then inject this interface object inside of the constructor,
    * and this will be the way we do our dependency injection.
    *
    * we need to create 2 beans for these 2 dependencies injection in
    * our application and tell spring how we want to load a user, and
    * then create a bean for password encoder. We can create those 2
    * beans inside main class (SpringSecurityJwtApplication).
    *
    * and for the userDetailsService, one way we can do this is to
    * implement and override the method from userDetailsService inside
    * UserServiceImpl.
    */
    private final UserDetailsService userDetailsService;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        super.configure(auth);
        /*
        * there are many ways to look for the users.
        * The first one is in memory, and then i pass in username and password
        * so that spring can use to check for users when users are trying to log into the application.
        *
        * And I can also use JDBC authentication. So I can create service class and then passing all
        * the queries and everything. And then use JDBC to make my own request and then override the
        * JDBC user detail manager configure. But we already have JPA, so we're not going to do that.
        *
        * But the one we're looking for is userDetailsService.
        * The userDetailsService is going accept a userDetailsService, which is a Bean that we have to
        * override and tell Spring how to go look for the users. Then we need password encoder, and we
        * do another Bean using BCryptPasswordEncoder for that and then pass it to passwordEncoder().
         */
        auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder);
    }

    /*
    * By default, Spring using a session policy that was stateful
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
//        super.configure(http);
        /*
        * disable cross site request forgery
         */
        http.csrf().disable()
    }
}
