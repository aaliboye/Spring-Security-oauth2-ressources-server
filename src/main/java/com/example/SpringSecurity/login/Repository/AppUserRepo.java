package com.example.SpringSecurity.login.Repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.SpringSecurity.login.model.AppUser;

public interface AppUserRepo extends JpaRepository<AppUser, Long> {
    AppUser findByUsername(String username);
}
