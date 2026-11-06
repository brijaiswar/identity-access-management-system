package com.wisebrains.iam.session;

import com.wisebrains.iam.model.SessionRefreshToken;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface SessionRefreshTokenRepository extends JpaRepository<SessionRefreshToken, Long> {
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select t from SessionRefreshToken t join fetch t.session s join fetch s.user where t.tokenHash = :hash")
    Optional<SessionRefreshToken> findByHashForUpdate(@Param("hash") String hash);
}
