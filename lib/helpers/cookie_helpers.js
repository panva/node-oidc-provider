import instance from "./weak_cache.js";

export function shouldWriteCookies(ctx) {
    const cookieConfig = instance(ctx.oidc.provider).configuration.cookies;
    
    // If a custom shouldWriteCookies function is provided, use it
    if (typeof cookieConfig.shouldWriteCookies === 'function') {
        return cookieConfig.shouldWriteCookies(ctx);
    }
    
    // Fallback to doNotSet flag from config.
    return !cookieConfig.doNotSet;
}