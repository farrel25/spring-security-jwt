package com.farrel.springsecurityjwt;

import java.util.ArrayList;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import com.farrel.springsecurityjwt.models.Role;
import com.farrel.springsecurityjwt.models.User;
import com.farrel.springsecurityjwt.services.UserService;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
public class SpringSecurityJwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityJwtApplication.class, args);
	}

	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	CommandLineRunner run (UserService userService) {
		return args -> {
			userService.saveRole(new Role(null, "ROLE_SUPER_ADMIN"));
			userService.saveRole(new Role(null, "ROLE_ADMIN"));
			userService.saveRole(new Role(null, "ROLE_MANAGER"));
			userService.saveRole(new Role(null, "ROLE_USER"));

			userService.saveUser(new User(null, "farrel", "farrel", "1234", new ArrayList<>()));
			userService.saveUser(new User(null, "athaillah", "athaillah", "1234", new ArrayList<>()));
			userService.saveUser(new User(null, "atha", "atha", "1234", new ArrayList<>()));
			userService.saveUser(new User(null, "putra", "putra", "1234", new ArrayList<>()));

			userService.addRoleToUser("farrel", "ROLE_SUPER_ADMIN");
			userService.addRoleToUser("farrel", "ROLE_ADMIN");
			userService.addRoleToUser("farrel", "ROLE_USER");
			userService.addRoleToUser("athaillah", "ROLE_ADMIN");
			userService.addRoleToUser("atha", "ROLE_MANAGER");
			userService.addRoleToUser("putra", "ROLE_MANAGER");
			userService.addRoleToUser("putra", "ROLE_USER");
		};
	}
}
