package com.farrel.springsecurityjwt.services;

import com.farrel.springsecurityjwt.models.Role;
import com.farrel.springsecurityjwt.models.User;

import java.util.List;

public interface UserService {

    User saveUser(User user);
    Role saveRole(Role role);
    void addRoleToUser(String username, String roleName);
    User getUser(String username);
    List<User> getAllUsers();
}
