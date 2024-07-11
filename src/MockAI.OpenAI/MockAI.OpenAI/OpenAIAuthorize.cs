// Copyright (c) IdeaTech. All rights reserved.

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace MockAI.OpenAI;

/// <summary>
/// Custom authorization attribute to check for an API key in the request header.
/// 自定义授权特性，用于检查请求头中的 API 密钥。
/// </summary>
public class ApiKeyAuthorizeAttribute : Attribute, IAuthorizationFilter
{
    private const string ApiKeyHeaderName = "apiKey";

    /// <summary>  
    /// Called to check if the request is authorized.
    /// 调用以检查请求是否被授权。
    /// </summary>
    /// <param name="context">The authorization filter context. 授权过滤器上下文。</param>
    public void OnAuthorization(AuthorizationFilterContext context)
    {
        if (!context.HttpContext.Request.Headers.TryGetValue(ApiKeyHeaderName, out var extractedApiKey))
        {
            context.Result = new UnauthorizedResult();
            return;
        }

        if (!extractedApiKey.ToString().StartsWith("sk-", StringComparison.OrdinalIgnoreCase))
        {
            context.Result = new UnauthorizedResult();
            return;
        }
    }
}
