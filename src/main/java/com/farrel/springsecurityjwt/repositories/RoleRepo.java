package com.farrel.springsecurityjwt.repositories;

import com.farrel.springsecurityjwt.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepo extends JpaRepository<Role, Long> {
    Role findByName(String name);
}
