package com.example.auth.center.infrastructure.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/** 權限資料表映射，權限碼採用 {@code 資源:動作} 命名，例如 {@code order:create}。 */
@Entity
@Table(name = "auth_permission")
public class PermissionEntity {

    @Id
    @Column(name = "id", length = 64, nullable = false)
    private String id;

    @Column(name = "code", length = 128, nullable = false, unique = true)
    private String code;

    protected PermissionEntity() {
    }

    public String getId() {
        return id;
    }

    public String getCode() {
        return code;
    }
}
