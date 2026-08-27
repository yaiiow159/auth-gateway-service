package com.example.sample.order;

import java.math.BigDecimal;

/** 示範用的訂單模型。 */
public record Order(String id, String ownerId, BigDecimal amount) {
}
