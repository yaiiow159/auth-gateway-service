package com.example.auth.gateway.support;

/**
 * 全域過濾器的執行順序。
 *
 * <p>把順序集中成常數而不是散落在各個 {@code getOrder()} 的魔術數字，
 * 是因為順序本身就是這條管線最重要的設計：任何一次調換都可能造成
 * 「未認證的請求被注入了身分」這種等級的安全問題。
 *
 * <p>數值越小越早執行。Spring Cloud Gateway 內建的路由過濾器排在 0 之後，
 * 因此所有安全相關的處理都必須是負數。
 */
public final class FilterOrder {

    /** 補齊 Request Id，必須最先執行，讓之後所有日誌都能帶上它。 */
    public static final int REQUEST_ID = -1000;

    /** 驗證 Token 並解析身分。 */
    public static final int AUTHENTICATION = -900;

    /** 依身分做粗粒度授權，必須在認證之後。 */
    public static final int AUTHORIZATION = -800;

    /** 剝除偽造 Header 並注入可信身分，必須在授權通過之後、路由之前。 */
    public static final int IDENTITY_PROPAGATION = -700;

    private FilterOrder() {
        throw new AssertionError("常數類別不應被實例化");
    }
}
