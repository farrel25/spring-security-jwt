package com.farrel.springsecurityjwt.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.stream.Collectors;

@Slf4j
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    /*
    * we need to bring the authentication manager because we're gonna be
    * calling the authentication manager to authenticate the user and
    * inject it in this class.
     */
    private final AuthenticationManager authenticationManager;

    public CustomAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    // we need to override 2 methods
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
//        return super.attemptAuthentication(request, response);
        /*
        * we need to call the authenticationManager, passing the user credentials,
        * and then let's spring do its magic.
         */
        // retrieve the username and password
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        log.info("Username is: {}", username);
        log.info("Password is: {}", password);

        // then we need to create an object of UsernamePasswordAuthenticationToken
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password);

        // Then we call authenticationManager to authenticate the user that is logging in
        return authenticationManager.authenticate(authenticationToken);
    }

    /*
    * whenever the login is successful, this method will be called,
    * then we had to send the access token and the refresh token to
    * the user. In this method is where we have to generate the token
    * and then send that token over the user. We can use the response
    * parameter to passing something in header or body. Which mean that
    * we need to have some sort of way to generate the token, signed
    * the token, and then send the token over the user. We can do
    * that by ourselves, but that's a lot of work. So we can use some
    * external library called auth0 java jwt.
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException, ServletException {
//        super.successfulAuthentication(request, response, chain, authResult);

        // to get the user that's been succesfully logged in
        // because getPrincipal returning an object, it will show error. So we need to do some casting
        User user = (User) authentication.getPrincipal();

        // setting up the algorithm
        // you won't do this (passing secret string) in a production
        Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());

        /*
        * create the token
        * pass something unique from the user inside withSubject(),
        * so you can identify the user by the specific token.
        *
        * withExpiresAt => set the token to be expired in 10 minutes
        * withIssuer => the author of this token, it is going to be the url of our app
         */
        String access_token = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + 10 * 60 * 1000))
                .withIssuer(request.getRequestURL().toString())
                .withClaim("roles", user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                .sign(algorithm);

        String refresh_token = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + 30 * 60 * 1000))
                .withIssuer(request.getRequestURL().toString())
                .sign(algorithm);

        // use the response too send those to the user in the front end
        response.setHeader("access_token", access_token);
        response.setHeader("refresh_token", refresh_token);
    }
}
