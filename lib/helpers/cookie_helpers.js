import instance from "./weak_cache.js";

export async function shouldWriteCookies(ctx) {
    const cookieConfig = instance(ctx.oidc.provider).configuration.cookies;
    
    // If a custom shouldWriteCookies function is provided, use it
    if (typeof cookieConfig.shouldWriteCookies === 'function') {
        return await cookieConfig.shouldWriteCookies(ctx);
    }
    
    // Fallback to doNotSet flag from config.
    return !cookieConfig.doNotSet;
}

export function clearAllCookies(ctx) {
    const cookieConfig = instance(ctx.oidc.provider).configuration.cookies;
    const clearCookiesAtAdditionalPaths = cookieConfig.clearCookiesAtAdditionalPaths || [];

    // First clear the cookies at the 'main' path.
    ctx.cookies.set(ctx.oidc.provider.cookieName("interaction"), null);
    ctx.cookies.set(ctx.oidc.provider.cookieName("resume"), null);
    ctx.cookies.set(ctx.oidc.provider.cookieName("session"), null);

    // Also clear cookies at any additional paths specified in the configuration.
    for (const path of clearCookiesAtAdditionalPaths) {
        ctx.cookies.set(ctx.oidc.provider.cookieName("interaction"), null, { path });
        ctx.cookies.set(ctx.oidc.provider.cookieName("resume"), null, { path });
        ctx.cookies.set(ctx.oidc.provider.cookieName("session"), null, { path });
    }
};