export default function getBaseToken(provider: any): {
    new (payload: any): {
        jti: string;
        kind: string;
        exp: number;
        consumed: boolean;
        grantId: string;
        expiresIn: number;
        readonly isValid: boolean;
        readonly isExpired: boolean;
        save(): Promise<string>;
        destroy(): any;
        consume(): any;
        readonly adapter: any;
        readonly expiration: any;
        getValueAndPayload<T>(): Promise<[string, {
                grantId?: string | undefined;
                header: any;
                payload: any;
                signature: string;
            }]>;
    };
    readonly expiresIn: any;
    readonly adapter: any;
    readonly IN_PAYLOAD: string[];
    find(token?: string, { ignoreExpiration }?: {
        ignoreExpiration?: boolean;
    }): Promise<{
        jti: string;
        kind: string;
        exp: number;
        consumed: boolean;
        grantId: string;
        expiresIn: number;
        readonly isValid: boolean;
        readonly isExpired: boolean;
        save(): Promise<string>;
        destroy(): any;
        consume(): any;
        readonly adapter: any;
        readonly expiration: any;
        getValueAndPayload<T>(): Promise<[string, {
                grantId?: string | undefined;
                header: any;
                payload: any;
                signature: string;
            }]>;
    } | undefined>;
    getTokenId(token: string): string;
    verify(token: string, stored: any, options: {
        ignoreExpiration: boolean;
    }): Promise<any>;
};
