package com.example.auth.center.infrastructure.persistence;

import java.util.List;
import java.util.Set;
import org.springframework.data.jpa.repository.JpaRepository;

interface RoleJpaRepository extends JpaRepository<RoleEntity, String> {

    List<RoleEntity> findByCodeIn(Set<String> codes);
}
