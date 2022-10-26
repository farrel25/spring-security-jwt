package com.farrel.springsecurityjwt.models;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.Collection;

@Entity
@Data // to set getter setter using lombok
@NoArgsConstructor // no argument constructor. from lombok
@AllArgsConstructor // it will create constructor on the fly
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;
    private String name;
    private String username;
    private String password;

    /**
     * because I want to load all the roles whenever I load the user
     * So I am going to use FetchType.EAGER
     */
    @ManyToMany(fetch = FetchType.EAGER)
    private Collection<Role> roles = new ArrayList<>();
}
