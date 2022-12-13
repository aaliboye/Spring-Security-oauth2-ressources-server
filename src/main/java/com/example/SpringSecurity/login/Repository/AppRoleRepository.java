package com.example.SpringSecurity.login.Repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.SpringSecurity.login.model.AppRole;

public interface AppRoleRepository extends JpaRepository<AppRole, Long>{

    AppRole findByRoleName(String roleName);
    
}
