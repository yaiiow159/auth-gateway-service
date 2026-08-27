package com.example.auth.center.infrastructure.persistence;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

/**
 * Spring Data 存取介面。
 *
 * <p>兩個查詢都以 {@code join fetch} 一次撈齊角色與權限。若交給 Lazy Loading 處理，
 * 每次登入都會退化成「1 次查使用者 + N 次查角色 + N*M 次查權限」的 N+1 問題 ——
 * 而登入正是整個系統中最不能慢的路徑之一。
 */
public interface UserJpaRepository extends JpaRepository<UserEntity, String> {

    @Query("""
            select distinct u from UserEntity u
            left join fetch u.roles r
            left join fetch r.permissions
            where u.username = :username
            """)
    Optional<UserEntity> findByUsernameWithAuthorities(@Param("username") String username);

    @Query("""
            select distinct u from UserEntity u
            left join fetch u.roles r
            left join fetch r.permissions
            where u.id = :id
            """)
    Optional<UserEntity> findByIdWithAuthorities(@Param("id") String id);
}
