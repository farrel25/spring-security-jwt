package com.farrel.springsecurityjwt.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import static java.util.Arrays.stream;
import static org.springframework.http.HttpStatus.FORBIDDEN;

/*
* After we're able to give the user an access and refresh token when they log in successfully.
* Next, we need to be able to take those token from the user, verify the token, and give them
* access to the app after we verify that the token is valid. To do that, we need this
* CustomAuthorizationFilter class that is going to intercept every request that comes into the
* app. After that, we need to add this CustomAuthorizationFilter class into our security
* configuration class
 */
@Slf4j
public class CustomAuthorizationFilter extends OncePerRequestFilter {

    /*
    * In this method, we're going to put all the logic to filter the request coming in, and
    * determine if the user has access to the app or not
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // check to see if this is not the login path, because I don't want to do anything and let it go through
        if (request.getServletPath().equals("/api/login")) {
            filterChain.doFilter(request, response);
        } else {
            /*
            * check to see if the user has authorization and set the user as the logged-in user
            * in the security context. First thing to do, try to access authorization header to
            * look for specific authorization header that should be the key for the token.
             */
            String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

            /*
            * whenever we send the request with the token, we're to put the word "Bearer", and
            * white space " ", and then the token
             */
            if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
                try {
                    // get the token by calling substringm then pass how manyletters we want to remove
                    String token = authorizationHeader.substring("Bearer ".length());
                    Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());

                    /*
                    * to create the verifier, we need the algorithm with the same scret that we use
                    * to encode the token. Then pass the algorithm to the verifier.
                    */
                    JWTVerifier verifier = JWT.require(algorithm).build();

                    // decode the token
                    DecodedJWT decodedJWT = verifier.verify(token);

                    // get username and roles from decoded token
                    String username = decodedJWT.getSubject();
                    String[] roles = decodedJWT.getClaim("roles").asArray(String.class);

                    // set them above in the authentication context
                    /*
                    * The reason why we have to do this conversion below is because we need
                    * to get those roles and convert them into something that extends
                    * GrantedAuthority which is SimpleGrantedAuthority. Because that's what
                    * Spring security expecting as the rules of the user
                     */
                    Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
                    stream(roles).forEach(role -> {
                        authorities.add(new SimpleGrantedAuthority(role));
                    });

                    UsernamePasswordAuthenticationToken authenticationToken =
                            new UsernamePasswordAuthenticationToken(username, null, authorities);

                    /*
                    * This is how we tell the Spring security that this is the user, their username, their roles.
                    * Then Spring will look at those user and roles to determine what resource they can access
                     */
                    // set the user and the security context holder
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                    filterChain.doFilter(request, response);
                } catch (Exception e) {
                    /*
                    * Let's say the token was not valid, we weren't able to verify it, or it expires,
                    * or something like that. So we need send something to the user so that they know
                    * what happens
                     */
                    log.error("Error logging in: {}", e.getMessage());
                    response.setHeader("error", e.getMessage());
                    response.setStatus(FORBIDDEN.value());
                    // response.sendError(FORBIDDEN.value());
                    // response.sendError(FORBIDDEN.value(), FORBIDDEN.getReasonPhrase());

                    // instead of setting headers as above, I want to actually send something in the response body
                    Map<String, String> error = new HashMap<>();
                    error.put("error_message", e.getMessage());

                    // I want this to be json. So we're going to use MediaType.APPLICATION_JSON_VALUE
                    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                    new ObjectMapper().writeValue(response.getOutputStream(), error);
                }
            } else {
                filterChain.doFilter(request, response);
            }
        }
    }
}
