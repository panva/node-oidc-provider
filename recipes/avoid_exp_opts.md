# Avoid excuting expensive operations in findAccount

- built for version: ^7.x
- no guarantees this is bug-free, no support will be provided for this, you've been warned, you're on
your own

This recipes will allow you to avoid executing expensive operations in findAccount after calling userinfo endpoint first time. 

If you execute some expensive operations like merge data from different sources (redis, mongodb, MYSQL, LDAP etc), this tips will help you.

When you authenticate first time, The findAccount function will called 2 times.

```bash
pre middleware GET /uaa/oauth/authorize/I0723uBcOXBDHJFZEt47Q&scope=openid%20profile
findAccount: 2, Time: 1
GrantId: null
post middleware GET /uaa/oauth/authorize/I0723uBcOXBDHJFZEt47Q&scope=openid%20profile
--------------------------------------------
pre middleware POST /uaa/oauth/token
findAccount: 2, Time: 2
GrantId: null
post middleware POST /uaa/oauth/token
--------------------------------------------
```

Then you will call userinfo endpoint, the `findAccount` will execute again. You have to persist your claims somewhere to avoid executing expensive operations.

```bash
pre middleware GET /uaa/user
findAccount: 2, call Time: 3
GrantId: uN5G4w45AGxrGP5yTo7CjTUjcXFvXkv4IQZqqNTWrUv
===> persist data to your store
post middleware GET /uaa/user
```

After doing that, each call of `userinfo` endpoint will retrieve data from your cache or your store.

```bash
pre middleware GET /uaa/user
findAccount: 2, call Time: 4
GrantId: uN5G4w45AGxrGP5yTo7CjTUjcXFvXkv4IQZqqNTWrUv
===> retrieve data from your store
{ username: 'toto' }
post middleware GET /uaa/user
--------------------------------------------
pre middleware GET /uaa/user
findAccount: 2, call Time: 5
GrantId: uN5G4w45AGxrGP5yTo7CjTUjcXFvXkv4IQZqqNTWrUv
===> retrieve data from your store
{ username: 'toto' }
post middleware GET /uaa/user
--------------------------------------------
```
There were two examples approachs:

`memeory cache` and `RedisAdapter`, you can adjust it as you want.

### Using memory cache

https://github.com/panva/node-oidc-provider/discussions/953

```js
const pMemoize = require('p-memoize');

async function claims(sub) {
  return { sub };
}

const memoizedClaims = pMemoize(claims, {
  maxAge: 10 * 1000, // for 10 seconds this won't be called again
  cachePromiseRejection: true,
  cacheKey: ([sub]) => sub,
});

async function findAccount(ctx, sub) {
  return {
    accountId: sub,
    claims: memoizedClaims.bind(undefined, sub),
  };
}

const memoizedFindAccount = pMemoize(findAccount, {
  maxAge: 10 * 1000, // for 10 seconds this won't be called again
  cachePromiseRejection: true,
  cacheKey: ([, sub]) => sub,
});

const configuration = {
  findAccount: memoizedFindAccount,
};
```


### Using Redis adapter

With this approach, *userinfo* data will persist in redis with key prefix `oidc:userinfo`.

To revoke userinfo redis, you could edit your redisAdapter in `revokeByGrantId` function.

```js
const redis = new RedisAdapter('userinfo');

static async findAccount(ctx, id) {
    const grantId = ctx.oidc.entities.AccessToken ? ctx.oidc.entities.AccessToken.grantId : null;
    console.log('GrantId: %s', grantId);
    let claimsData;
    try {
        if (grantId) {
            const data = await redis.find(grantId);
            if (!data) {
                console.log("persist data to redis")
                // Expensives operations
                // You could execute some expensive operations here
                // merge data from different sources (redis, mongodb, MS-SQL, LDAP etc)
                // then create your claimsDataObject
                claimsData = {username: 'toto'};
                // and persist claimsDataObject in redis or other store
                await redis.upsert(grantId, claimsData);
            } else {
                console.log("retrieve data from redis")
                claimsData = data;
            }
        }
    } catch (e) {
        console.log(e)
    }

    return {
        accountId: id,
        claims() {
            return {...claimsData}
        }
    }
}
```
