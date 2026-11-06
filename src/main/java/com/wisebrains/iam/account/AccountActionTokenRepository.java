package com.wisebrains.iam.account;

import com.wisebrains.iam.model.AccountActionToken;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;
import java.time.Instant;

public interface AccountActionTokenRepository extends JpaRepository<AccountActionToken, Long> {
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select token from AccountActionToken token join fetch token.user where token.tokenHash = :tokenHash and token.purpose = :purpose")
    Optional<AccountActionToken> findForUpdate(
            @Param("tokenHash") String tokenHash,
            @Param("purpose") String purpose);

    List<AccountActionToken> findAllByUserIdAndPurposeAndConsumedAtIsNull(Long userId, String purpose);

    @org.springframework.data.jpa.repository.Modifying
    @Query("delete from AccountActionToken token where token.expiresAt < :cutoff or token.consumedAt < :cutoff")
    int deleteExpiredOrOldConsumed(@Param("cutoff") Instant cutoff);
}
