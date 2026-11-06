package com.wisebrains.iam;

import com.wisebrains.iam.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);

    Optional<User> findByEmail(String email);

    boolean existsByUsername(String username);

    boolean existsByEmail(String email);

    List<User> findAllByMfaSecretIsNotNull();

    List<User> findAllByPendingMfaSecretIsNotNull();

    @Query("select count(distinct u) from User u join u.roles role where u.enabled = true and role.name = :roleName")
    long countEnabledByRoleName(@Param("roleName") String roleName);
}