export default function getClientCredentials({BaseToken}: {
    BaseToken: any;
}): {
    new (): {
        [x: string]: any;
    };
    [x: string]: any;
};
