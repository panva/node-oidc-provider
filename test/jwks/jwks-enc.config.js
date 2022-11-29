import getConfig from '../default.config.js';

const config = getConfig();

config.features.encryption = { enabled: true };

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
      e: 'AQAB',
      n: '-WKKrkieWMKX_SluQKq4i9CyEWAFzTxgpoxkb2_4qp1FLi2HjJVQpchAt4A1M8sPiLo2jM0qebslViFqOPgx5OzJEUQ7cegNb2v6pH47BhcucUHfZr85upxD_mvK4rjpn2D7r_mfZP62clYotvJsKco5rgrN1rpIPuUSxw0HJcyJLiLAeCtPOsJx81y3ekE46vuYqYMmdN12AnGJhW0SELxm02XwlAUcx6nrkGvP4RJf-B1VbBtR2wUCQHbtc9aZ6n8qZ2AMQ7Q_61PZVINit-i64u6vnvzTosKNJsvwR_JytgYOnqCxUyhdqjfYnO0neNttNpsdjLAhfdXEMqCJBw',
      d: '1pfvEe23JFW-h8BA-TBuwRECSWVBWMvdtzMTsbi-V8IhJ41SGKzbyuw4lC6kmT7gzRy_mAVryXg6tpTmXMNl28HNeyglpuyxsvFNqoJcs-76rcarQDTIrkWNVL7YxKOtlNHVgiXg_P0ZbeWp_1M3s_YqEBOH8IA3brebouEZB3H4tPXv7R4NDgpm5lFz9tS5iJQEuD9BBrzz5Dp6PSZnq72_6DmlcF21YbNLcJr7W70fAr-kYapEfd_sH817_it9rnOaawHh6ilJ1Mc4ZJQlO6dJMMH-RgF1dXR82YzMX7fgNtjvA8kP_SSnW0bTPkzJxfxwFGU3KCticYa-UXI0QQ',
      p: '_pL3yvepFY70-XDe-R5ld6VVXAAJrySLCcaI-wcDkv1G_RRd6nlz9Cu65UbkhGGHR4-goUAlOiLz75kWtuK0Tmp5WFeiVRa9uBwW3gntE7W5Dwfv2ObVtlt1N7dHWNOsiRtQSKT8lhxlJmefakqlmvxrbhuteZerw1oPOuLhhvc',
      q: '-sgiEQ-clwCqk3GcnF_6JlVXAgUJPn0LjKZSTCDODSujez3UlXhLD5u4yBQYxtLlMRXdjaAiCxSWtNU3pjHOmLLsORPxeszbRoNg6TBUCsDxOzivZu4L_SKBVjUIYeduA8HxtqDgIOMpD8RS-8RNYIyke1aSQOPa9v1EJQ-AOnE',
      dp: 'EGVs2kC7Pi037_zqD4d6p4sZhVRnS0WCQv3rgqd__m6brN8r8VcjNb2_StcXDsOtT9mbUedsvmLT7UGh6eOOE2LeL-dtCCfvzjTY8DIZd-SDZ8luFD1B1H3tfcorKThw61-7-wHNVum7Rg70gIcQRXwueygDM0qmgG2Df5pvRh8',
      dq: '9esPTP-sJH9oxdFhLA8J9FE3UymxGO_yRWhLx49bv5qNY6sMLc6afKHNn5XlfgMM8QdqDRl8iLUV3BpByd2JpD_AWXBvGmaMmCb4_3J-11TAubwqdJr2crJFdk3m_Gq_fTvQVbCIWHepqmZwoaar4gPIv5HzNWK7M_zDuDvtGGE',
      qi: 'Sx5syp_CZsDpIBBpawXrNZcExob3m3sakv6tvIHvhqchSgODUv2X0WVxh8V_hA02bdDOsfbmHcg_pBoj7-NEi1ZhRVOSHwGLgD2G03FQduJI6OWK-1lAvojp_dNYw6ctuJOfvLNIInw9DiTr7hO9QEB1WBddmtpwlDHkczvz-t4',
      kty: 'RSA',
      alg: 'RSA-OAEP',
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
      crv: 'P-256',
      x: 'LBmYqXV6GXP3-KH26M4FARYEgaTs2_w0CB6p42oVi2g',
      y: '4b6YSQx6deoyOkPELa_R9vfIm0wEEqrCOHQ_7OCkOEw',
      d: 'Ure4tn0SJrst29oCjWRcSeb4zzfvuOxgQ0jbh8ASWT4',
      kty: 'EC',
      alg: 'ECDH-ES',
    },
    {
      crv: 'Ed448',
      x: 'bSI-zbfp5DeKlG1-tyQi4_2OZIQdoQYv79BKtotgOkCUYLyuvVQfasiEbpv1RzMPbYLu6Qrxf7QA',
      d: '6iCElWuLMOvd2iNXGX5_5FkOKJcoSIC0nhmCaZKmT6Z7aUKovF2qWB4XoFtB6ml8PEI6ch2EaJky',
      kty: 'OKP',
    },
    {
      crv: 'X448',
      x: 'VGcaaNI0fHoa0A39PptMppoJU37-WRSh-p4qjPVpORvV-USWGKMAENK22n_HD3zbqsFp9biK7ws',
      d: 'KD0qCaSnNOssm-_LADm7wR429a5eikurwiynRxGLLyqbdUnLszbg2faBgwdsFvidcvJ-3HSoUZM',
      kty: 'OKP',
    },
  ],
};

export default {
  config,
};
