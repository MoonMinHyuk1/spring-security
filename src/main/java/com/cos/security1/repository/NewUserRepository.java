package com.cos.security1.repository;

import com.cos.security1.model.NewUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface NewUserRepository extends JpaRepository<NewUser, Long> {
    public NewUser findByUsername(String username);
}
