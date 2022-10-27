package com.farrel.springsecurityjwt.controllers;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.farrel.springsecurityjwt.models.Role;
import com.farrel.springsecurityjwt.models.User;
import com.farrel.springsecurityjwt.services.UserService;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.*;
import java.util.stream.Collectors;

import static org.springframework.http.HttpStatus.FORBIDDEN;

@RestController
@RequiredArgsConstructor
@RequestMapping(path = "/api")
public class UserController {

    private final UserService userService;

    @GetMapping("/users")
    public ResponseEntity<List<User>> getAllUsers() {
        return ResponseEntity.ok().body(userService.getAllUsers());
    }

    @PostMapping("/user/save")
    public ResponseEntity<User> saveUser(@RequestBody User user) {

        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/user/save").toUriString());

        /*
          instead of returning ok (code 200). it's more precise to send a 201.
          Which mean something was created on the server resource.
         */
        return ResponseEntity.created(uri).body(userService.saveUser(user)); // return code 201
    }

    @PostMapping("/role/save")
    public ResponseEntity<Role> saveRole(@RequestBody Role role) {
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/role/save").toUriString());
        return ResponseEntity.created(uri).body(userService.saveRole(role));
    }

    @PostMapping("/role/addtouser")
    /*
    * This is not going to return anything. So we're going to pass in the question mark inside ResponseEntity.
    * We need to get the username and role name, so we can give it to the service
    */
    public ResponseEntity<?> addRoleToUser(@RequestBody RoleToUserForm form) {
        userService.addRoleToUser(form.getUsername(), form.getRoleName());
        return ResponseEntity.ok().build();
    }

    /*
    * Whenever the access_token expires, Front-end will wait for the response to get something like forbidden
    * or something like that, and FE will look at the code or some specific message, and FE will determine that
    * it's because the user's token has expired. So the FE look for the refresh_token, and then send another
    * request immediately.
    *
    * So everything happened seamlessly, like the user doesn't ever realize that their token was expired, and
    * there was another request that was made to actually get them an access token. So that means that we need
    * to have away to take the refresh_token, verify it, confirm that it's valid, and then send them another
    * access_token so that they can keep using our app and access resources with the access_token.
    *
    * We want to create another endpoint where the user can set up request, so that they can renew their token.
    * So they're going to send the refresh token, and then we're going to take the refresh_token, validate it,
    * and then give them another access token.
    */
    @GetMapping("/token/refresh")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            try {
                // get the token by calling substring then pass how many letters we want to remove
                String refresh_token = authorizationHeader.substring("Bearer ".length());

                // get the algorithm
                Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());

                /*
                 * to create the verifier, we need the algorithm with the same secret that we use
                 * to encode the token. Then pass the algorithm to the verifier.
                 */
                JWTVerifier verifier = JWT.require(algorithm).build();

                // decode the token
                DecodedJWT decodedJWT = verifier.verify(refresh_token);

                // get username and roles from decoded token
                String username = decodedJWT.getSubject();

                // load that user in our database to make sure that this user actually exists in our system
                User user = userService.getUser(username);

                // set them above in the authentication context
                String access_token = JWT.create()
                        .withSubject(user.getUsername())
                        .withExpiresAt(new Date(System.currentTimeMillis() + 10 * 60 * 1000))
                        .withIssuer(request.getRequestURL().toString())
                        .withClaim("roles", user.getRoles().stream().map(Role::getName).collect(Collectors.toList()))
                        .sign(algorithm);

                // use the response to send those to the user in the front end
                // response.setHeader("access_token", access_token);
                // response.setHeader("refresh_token", refresh_token);

                // instead of setting headers as above, I want to actually send something in the response body
                Map<String, String> tokens = new HashMap<>();
                tokens.put("access_token", access_token);
                tokens.put("refresh_token", refresh_token);

                // I want this to be json. So we're going to use MediaType.APPLICATION_JSON_VALUE
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(), tokens);
            } catch (Exception e) {
                /*
                 * Let's say the token was not valid, we weren't able to verify it, or it expires,
                 * or something like that. So we need send something to the user so that they know
                 * what happens
                 */
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
            throw new RuntimeException("Refresh token is missing");
        }
    }

    @Data
    class RoleToUserForm {
        private String username;
        private String roleName;
    }
}

