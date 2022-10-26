package com.farrel.springsecurityjwt.repositories;

import com.farrel.springsecurityjwt.models.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepo extends JpaRepository<User, Long> {

    User findByUsername(String username);
}
