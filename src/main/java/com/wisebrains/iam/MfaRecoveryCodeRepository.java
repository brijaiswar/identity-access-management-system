package com.wisebrains.iam;

import com.wisebrains.iam.model.MfaRecoveryCode;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;

public interface MfaRecoveryCodeRepository extends JpaRepository<MfaRecoveryCode, Long> {
    @Modifying
    @Query("update MfaRecoveryCode code set code.usedAt = :usedAt where code.codeHash = :codeHash and code.user.id = :userId and code.usedAt is null")
    int consumeIfUnused(@Param("userId") Long userId,
                        @Param("codeHash") String codeHash,
                        @Param("usedAt") Instant usedAt);

    void deleteAllByUserId(Long userId);
}
