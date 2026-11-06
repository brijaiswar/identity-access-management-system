package com.wisebrains.iam;

import com.wisebrains.iam.model.LoginAttemptBucket;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface LoginAttemptBucketRepository extends JpaRepository<LoginAttemptBucket, String> {
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select b from LoginAttemptBucket b where b.bucketKey = :key")
    Optional<LoginAttemptBucket> findByKeyForUpdate(@Param("key") String key);

    @Modifying
    @Query("delete from LoginAttemptBucket b where b.windowStartedAt < :windowCutoff and (b.blockedUntil is null or b.blockedUntil < :now)")
    int deleteInactiveBefore(@Param("windowCutoff") java.time.Instant windowCutoff,
                             @Param("now") java.time.Instant now);
}
