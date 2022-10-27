package com.farrel.springsecurityjwt.security;

/*
 * authentication meaning who. Verifies who you are who you say you are.
 *
 * authorization meaning what they can access in the application, and
 * we're going to control that using the role. It will decide if you have
 * permission to access a resource.
 */

import com.farrel.springsecurityjwt.filter.CustomAuthenticationFilter;
import com.farrel.springsecurityjwt.filter.CustomAuthorizationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;

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
    * and then inject this interface object inside the constructor,
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
        * The first one is in memory, and then I pass in username and password
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
    * By default, Spring using a session policy that was stateful. So Spring will save something
    * in memory, tracking the users by giving them a cookie (that's why spring generate random
    * password). But we don't want to use this system. We will use Json Web Token system. When
    * the user logged in, we give them a token, and we don't keep track of the user with no cookies
    * or anything like that. The way we configure this is by configuring the HttpSecurity.
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
//        super.configure(http);

        // configuration of customized login path
        CustomAuthenticationFilter customAuthenticationFilter = new CustomAuthenticationFilter(authenticationManagerBean());
        customAuthenticationFilter.setFilterProcessesUrl("/api/login");

        // The first thing to configure the HttpSecurity is to disable cross site request forgery.
        http.csrf().disable();

        // to specify stateless
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        /*
        * Btw, the order of http configuration is matters.
        * If we want to allow certain path, we can to do something like this.
        * Pass whatever path that we don't want to secure. Then permit all.
        * Btw, Spring is already taken care of login path because you can see
        * that login path is not defined in our controller. But if you want to
        * see where login path is coming from, just open UsernamePasswordAuthenticationFilter
        * class that we extend it inside CustomAuthenticationFilter, then you
        * will see "/login" inside DEFAULT_ANT_PATH_REQUEST_MATCHER. And if you
        * want to change that, we can actually override it with our own custom
        * authentication filter. Look at the top of this body method for the
        * configuration of customized login path.
         */
        // http.authorizeRequests().antMatchers("/login").permitAll();
        // http.authorizeRequests().antMatchers("/api/login/**").permitAll();
        http.authorizeRequests().antMatchers("/api/login/**", "/api/token/refresh/**").permitAll();

        // if someone access /api/user/** and everything after that (/user/...), then they need to have user role
        http.authorizeRequests().antMatchers(GET, "/api/users/**").hasAnyAuthority("ROLE_USER");

        http.authorizeRequests().antMatchers(POST, "/api/users/save/**").hasAnyAuthority("ROLE_ADMIN");

        // we're going to allow everyone to be able to access this app at this point
//        http.authorizeRequests().anyRequest().permitAll();

        /*
        * But we don't want to do permitAll(), because it means that we just throw our security out of the window.
        * We want to do authenticate, so we want everyone to be authenticated
         */
        http.authorizeRequests().anyRequest().authenticated();


        /*
        * we need authentication filter so that we can check the user whenever they're
        * trying to log in. we're going to pass a null because we don't have any filter yet.
        * Therefore, we're going to create CustomAuthenticationFilter class that extends
        * UsernamePasswordAuthenticationFilter
         */
        // http.addFilter(null);
        // http.addFilter(new CustomAuthenticationFilter(authenticationManagerBean()));
        http.addFilter(customAuthenticationFilter);

        /*
        * We need to make sure that this filter comes before the other filters, because
        * we need to intercept every request before any other filters. And then I want to
        * tell it what it's for which means UsernamePasswordAuthenticationFilter.
         */
        http.addFilterBefore(new CustomAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
