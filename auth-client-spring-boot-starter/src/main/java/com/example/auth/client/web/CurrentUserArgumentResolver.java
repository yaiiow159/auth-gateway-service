package com.example.auth.client.web;

import com.example.auth.client.annotation.CurrentUser;
import com.example.auth.client.context.MissingIdentityException;
import com.example.auth.contract.AuthenticatedUser;
import org.springframework.core.MethodParameter;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

/**
 * 讓 {@code @CurrentUser AuthenticatedUser} 直接出現在 Controller 的方法簽章上。
 *
 * <p>身分在 {@link GatewayIdentityFilter} 就已經解析並驗證完成，這裡只是取出來，
 * 因此不會有「每個參數重解析一次 Header」的浪費。
 */
public class CurrentUserArgumentResolver implements HandlerMethodArgumentResolver {

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return parameter.hasParameterAnnotation(CurrentUser.class)
                && AuthenticatedUser.class.isAssignableFrom(parameter.getParameterType());
    }

    @Override
    public Object resolveArgument(MethodParameter parameter,
                                  ModelAndViewContainer mavContainer,
                                  NativeWebRequest webRequest,
                                  WebDataBinderFactory binderFactory) {
        Object user = webRequest.getAttribute(
                GatewayIdentityFilter.IDENTITY_ATTRIBUTE, RequestAttributes.SCOPE_REQUEST);

        CurrentUser annotation = parameter.getParameterAnnotation(CurrentUser.class);
        boolean required = annotation == null || annotation.required();
        if (user == null && required) {
            throw new MissingIdentityException("請求未攜帶網關身分，可能是繞過網關直接呼叫本服務");
        }
        return user;
    }
}
