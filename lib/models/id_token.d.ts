export default function getIdToken(provider: any): {
    new (available: any, sector: any): {
        extra: {};
        available: {};
        sector: {};
        scope: {};
        mask: {};
        set(key: any, value: any): void;
        payload(): any;
        sign(client: any, { use, audiences, expiresAt, noExp, }?: {
            use?: string | undefined;
            audiences?: string | undefined;
            expiresAt?: number | undefined;
            noExp?: boolean | undefined;
        }): Promise<any>;
    };
    readonly expiresIn: any;
    validate(jwt: any, client: any): Promise<any>;
};
