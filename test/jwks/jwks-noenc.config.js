import getConfig from '../default.config.js';

const config = getConfig();

config.features.encryption = { enabled: false };

config.jwks = {
  keys: [
    {
      e: 'AQAB',
      n: '2s3t1LBJxVpq0aD7GhZYUANkcIzmT6CFAEYe87xpyBUNiGMsLAmoNcyOSs5z3YYdkWCWuFETyr2n7hWN2tYNDR0TegYLdo_tUgvJlXYZRnFf7Jle8FLv2n9BGmFobrVRXoa5EjlccgbnwtibnN0XYDoTgSsoODsMsAsntnPTSQJ2XPmBNg8YlS-EAze7-3IZ_kYGa62bzdOCnTY3M8_HYvDGTLJeUrZfxasncQDVmbCxTWs8H6wKVx6OxwJmyDLFipzTtk9kPh6W37m0StKQcLDTzq3RYD9-o7Rj7qL6KXy6B_hbHP9aKK3Bd46-iYhfTP3ddU-wHJPWGGswr_PAow',
      d: 'Hv4aWQ0bdfPnu4fE6Z4Opk7EtFiQ6uh-zlogWj_u7-NjhlUd1aMMi4pNAXWa3d74YzY-Qx9g4U_Z8JRnAn9dW-UpdBhVGVcrs3pt9FjFHcBDaR0UYJAu31E1JIp1o3DVdME6h8VOPeySeXv7Fs4OWJgBWUOGr-hVVL5Pwr1HSUjn5f4GKo64VMFYsnIiz5IldSnp4wwwT1X7G8ZRbtCKOQ_4lt17U_gLVAiHgRWlN99t5Dv3jckolRMXGTQ6uw_os9hGhNJ3D4cIBfDzsjrxzI5O7zt46neqBSBjnPy0z2G6mnjM6lUHxIzsLxa6XZjdjqqmqPnNMAbYNHDpl-hbWQ',
      p: '9rjHyDLJllALPY_uquBWxtfhdFGTq2smcAR5wCccCFK9IpnT6gSaEQua-3NNL0WChXIhbrUjJV6Tj8kcYoxUjIY1nZmU6Dr9j6rika7Vja86z69ewaE4yA8I5hJcmz9oCQRB_JkVY6tDB49aLrgBtIalsj-qICetpMYSEOAraj8',
      q: '4whieZi3S7yWfOTFRJK8-2sFwjKknYdfmITJOkP-z4mzsL9N6plp9Pz4OE0XuCg0TMsMli-G-z80ezgpB_nw0PmQ3uHvIfj6YI6-Nx8u89KVYrKPc01IDtV3GhpewTKKAXOxT9cr151qQ8P_rv_ZejldEYuet_ncui4Nnd9WaJ0',
      dp: 'i160VG4EHCoZP2x4GQTjYC4BCLEwZsv_iZWtpRMyraz3dH1LDU4OLgTNRq_KcSKl6XYgVqZyNSDo4Hdt1mmJNVx3GxDv4gO4yphwpnUJ46CR61IYh-7n4XNExpqmv3gg7778-5EKWSQcmD-tZOjC5dSN81QtaT6gw4y0Fd5cCAc',
      dq: 'TZ5iPHxPvl79fDmij-0zGynd0CUMTqcnsbdELN1uUnobqwPcmaZVqWKLYoRI5bcpGlAZP4eEOIXFZZMvxABZqriIJQtNfGno__YNZj8NCGMom5O8o4j6Z8fnbk8xsg-bSx_IsSk5Xf_9gqmR0ry6F6VhAkyfuPp90lFIan8exak',
      qi: '5maXjtEVKJGlrQUnD6A8Wumf8AcvDTs5wqHt9s8zXGjmXneaQMOC9xUbzd5nvoX7JOOlqIqWXMTH0BVfRlLqyLU-ZsAGIhBXs7Sz0_Djeq7liRdsjZRbgukp_Egs68XPdVCB-to-R5JVfnrQaWvxqFZbz5OzoUS2JYwwBJvlS8Y',
      kty: 'RSA',
    },
    {
      e: 'AQAB',
      n: 'pyugU-aphpnvdsQwYJptGICF2uXUdKCOBay8PrXbcOOBkaohQfKS8iYSUZYqULCjB8R7uXBc_XrQ17pgDLDDTTdReRpbuxZ_-tfZFh4-gM2vF175IMF8S4ZfIVPeVZWIVBtRPHp5kt9pl_xMqCjNmzwgHoUiJ-iVJ9mQmXq8h_NBEGMuJ3YmcdiE_8uaA9bX_Hi0w73B0S8aB8EFXZ-Z1Ln15qBcpHAvxNT1_bYjL4P14Vs6xcDfYBNDm05lrZJmng_bsqJh6DOYFiqgAVaqA1De-mMaYxiEmZ1M8Tfa9idoKQJK40k8X2yWIeGIEfGurRiHQlRafXPTWTSx-zLaMw',
      d: 'oK0W8e2ffadRedcCJKfpOga2IXqMJPj46M1pNeE3pR6Wt_pM8wUDZklfjBmIXHwahum8fbVZO62jM-aIUUpIvVvxLDRAfOcYZXK3zkGNk-GebBk13Nz76d-iafchmSMboLOM9lNFrPydkp7G0048qPs2Z_9QoAk169J64HoO4Z9H0NaMewAKwHVwX-4TNQjPycPCWGTmaFkTYIrVtgYIV69owdcxnqBcnAdgFLlHiRKDve4cVm2OD8tTpMV_F0fw5ApkgErC4U6hHdrzfX1FGczLfq89sH0yf-9cDDLYJWryjDf9badvkaLg3bASCCk5L7NwqSqiFsHrQYJpCedosQ',
      p: '2ynbGuqqiIo5tQ3zoorN0--Rrpjm90_w8zmY273k94_jMx-3Hw5gVk6YiXhzfOfwJb-G7dXkO_2WlRDEdL6mw6oIjKh1mYXimJCownXSLLAjaj6xb_17RzoYOr-ktLMLdH3GlLtcW7XvEogihNzMrS6jhwDWsVpGMXI0Q0jswMk',
      q: 'w0SeDnGW8YE4oUaESXDNI_vJUcAWR-Fnp67C1QCdDuDZ_noqVDICMoEM83avZA_ukY5JrZD0OmmQqLRrJOfSBR3umui9HhpqtKreN0tPayJDR2NsZWLRj4ce5n2LgfJRsPLFW-sySGz5dDxvb2BCXxTtQWRuvINpUT2vhtTl3Rs',
      dp: 'whDeI4eIWj-LufcQte2TNQf-SEy8uGHhSn7GDE6qYUzYMnzy-l0QkVwnVhOCsCfxTnu6TwAHideTb4vZakcoBDqcN3E0MS2M6OuvhAIwicGumnXJSRF8CCY5Lkxk3F1u10hIf4sozUzc1dwWNPAPjYqu4uyrL4Bwh3hJLwt0GYE',
      dq: 'tWzcmbjqMMsKLbYSFRYsU6GOJFmfmfuQzlhuh29BfeBmSq2BBKdOKVSEDvUX8pVm6HBWfmAuutL4Z_bxkeGd3ck4t09E32JWADS9sIxVZsn3zq1Oukh9QqidijPdWcgmJIz71_KHzokJoPjB5K6AHE2aPuasiJRkVupEWrcWNz8',
      qi: 'g0nkvs45TW4bHqas84jGQZSGPA1wn6lXnPO7_1oHItQFKIbn-APf5QApm6gjVN7E0chI2zVylmsABSHq5b-bIABvI1y-P-WCCiqhz5UJyklETa1K0xJyqUYF3G_LmSyrpj_0CZReGevFXQyV1mA5mt-qtkWl_vTcGmxepAksmnQ',
      kty: 'RSA',
      alg: 'RS256',
    },
    {
      crv: 'secp256k1',
      x: 'ADwk2-e--j0e-BPXlgJ_d7funjsWA8fi98u2uVYQUaU',
      y: 'J9wWPI_2hUxe3PkygNSaiLoUlM2sBPYVREb7EvrXjq0',
      d: 'epWVqvzY0IWne_lJEmEljLmrjbCwWWBe2ZoX_jjUHgM',
      kty: 'EC',
    },
    {
      crv: 'P-256',
      x: '0pm-JC6KeQqFwxdTLsBdtnrT4hV6VDlv3AWE6BSyFSk',
      y: 'ZvRmSa23_647WNcK_gkp5r8Jm4_9MnuyClguRYvu7Ik',
      d: 'niQR1Er0ZrssEGQupuRWroxsn9rvgrgkcz8jR6dYg_o',
      kty: 'EC',
    },
    {
      crv: 'Ed448',
      x: 'bSI-zbfp5DeKlG1-tyQi4_2OZIQdoQYv79BKtotgOkCUYLyuvVQfasiEbpv1RzMPbYLu6Qrxf7QA',
      d: '6iCElWuLMOvd2iNXGX5_5FkOKJcoSIC0nhmCaZKmT6Z7aUKovF2qWB4XoFtB6ml8PEI6ch2EaJky',
      kty: 'OKP',
    },
  ],
};

export default {
  config,
};
