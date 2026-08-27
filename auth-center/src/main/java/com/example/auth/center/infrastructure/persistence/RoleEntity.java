package com.example.auth.center.infrastructure.persistence;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;
import java.util.LinkedHashSet;
import java.util.Set;

/** 角色資料表映射，一個角色聚合多個權限，是 RBAC 的核心中介。 */
@Entity
@Table(name = "auth_role")
public class RoleEntity {

    @Id
    @Column(name = "id", length = 64, nullable = false)
    private String id;

    @Column(name = "code", length = 64, nullable = false, unique = true)
    private String code;

    @ManyToMany(fetch = FetchType.LAZY, cascade = {CascadeType.PERSIST, CascadeType.MERGE})
    @JoinTable(name = "auth_role_permission",
            joinColumns = @JoinColumn(name = "role_id"),
            inverseJoinColumns = @JoinColumn(name = "permission_id"))
    private Set<PermissionEntity> permissions = new LinkedHashSet<>();

    protected RoleEntity() {
    }

    public String getId() {
        return id;
    }

    public String getCode() {
        return code;
    }

    public Set<PermissionEntity> getPermissions() {
        return permissions;
    }
}
