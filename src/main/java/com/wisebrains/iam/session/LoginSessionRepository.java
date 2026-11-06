package com.wisebrains.iam.session;

import com.wisebrains.iam.model.LoginSession;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

public interface LoginSessionRepository extends JpaRepository<LoginSession, String> {
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select s from LoginSession s join fetch s.user where s.id = :id")
    Optional<LoginSession> findByIdForUpdate(@Param("id") String id);

    @Query("select s from LoginSession s join fetch s.user where s.user.id = :userId and s.revokedAt is null and s.expiresAt > :now order by s.lastUsedAt desc")
    List<LoginSession> findActiveForUser(@Param("userId") long userId, @Param("now") Instant now);

    @Query("select s from LoginSession s join fetch s.user where s.user.id = :userId and s.id = :id")
    Optional<LoginSession> findOwnedById(@Param("userId") long userId, @Param("id") String id);

    @Modifying
    @Query("delete from LoginSession s where s.expiresAt < :cutoff or (s.revokedAt is not null and s.revokedAt < :cutoff)")
    int deleteExpiredOrOldRevoked(@Param("cutoff") Instant cutoff);
}
