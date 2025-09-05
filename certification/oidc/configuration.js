import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';

import { dirname } from 'desm';

const pkg = JSON.parse(
  fs.readFileSync(path.resolve(dirname(import.meta.url), '../../package.json'), {
    encoding: 'utf-8',
  }),
);

const enabledJWA = structuredClone({ ...await import('../../lib/consts/jwa.js') });

const clientAuthMethods = [
  'none',
  'client_secret_basic',
  'client_secret_jwt',
  'client_secret_post',
  'private_key_jwt',
  'self_signed_tls_client_auth',
];

const keys = [
  {
    d: 'VEZOsY07JTFzGTqv6cC2Y32vsfChind2I_TTuvV225_-0zrSej3XLRg8iE_u0-3GSgiGi4WImmTwmEgLo4Qp3uEcxCYbt4NMJC7fwT2i3dfRZjtZ4yJwFl0SIj8TgfQ8ptwZbFZUlcHGXZIr4nL8GXyQT0CK8wy4COfmymHrrUoyfZA154ql_OsoiupSUCRcKVvZj2JHL2KILsq_sh_l7g2dqAN8D7jYfJ58MkqlknBMa2-zi5I0-1JUOwztVNml_zGrp27UbEU60RqV3GHjoqwI6m01U7K0a8Q_SQAKYGqgepbAYOA-P4_TLl5KC4-WWBZu_rVfwgSENwWNEhw8oQ',
    dp: 'E1Y-SN4bQqX7kP-bNgZ_gEv-pixJ5F_EGocHKfS56jtzRqQdTurrk4jIVpI-ZITA88lWAHxjD-OaoJUh9Jupd_lwD5Si80PyVxOMI2xaGQiF0lbKJfD38Sh8frRpgelZVaK_gm834B6SLfxKdNsP04DsJqGKktODF_fZeaGFPH0',
    dq: 'F90JPxevQYOlAgEH0TUt1-3_hyxY6cfPRU2HQBaahyWrtCWpaOzenKZnvGFZdg-BuLVKjCchq3G_70OLE-XDP_ol0UTJmDTT-WyuJQdEMpt_WFF9yJGoeIu8yohfeLatU-67ukjghJ0s9CBzNE_LrGEV6Cup3FXywpSYZAV3iqc',
    e: 'AQAB',
    kty: 'RSA',
    n: 'xwQ72P9z9OYshiQ-ntDYaPnnfwG6u9JAdLMZ5o0dmjlcyrvwQRdoFIKPnO65Q8mh6F_LDSxjxa2Yzo_wdjhbPZLjfUJXgCzm54cClXzT5twzo7lzoAfaJlkTsoZc2HFWqmcri0BuzmTFLZx2Q7wYBm0pXHmQKF0V-C1O6NWfd4mfBhbM-I1tHYSpAMgarSm22WDMDx-WWI7TEzy2QhaBVaENW9BKaKkJklocAZCxk18WhR0fckIGiWiSM5FcU1PY2jfGsTmX505Ub7P5Dz75Ygqrutd5tFrcqyPAtPTFDk8X1InxkkUwpP3nFU5o50DGhwQolGYKPGtQ-ZtmbOfcWQ',
    p: '5wC6nY6Ev5FqcLPCqn9fC6R9KUuBej6NaAVOKW7GXiOJAq2WrileGKfMc9kIny20zW3uWkRLm-O-3Yzze1zFpxmqvsvCxZ5ERVZ6leiNXSu3tez71ZZwp0O9gys4knjrI-9w46l_vFuRtjL6XEeFfHEZFaNJpz-lcnb3w0okrbM',
    q: '3I1qeEDslZFB8iNfpKAdWtz_Wzm6-jayT_V6aIvhvMj5mnU-Xpj75zLPQSGa9wunMlOoZW9w1wDO1FVuDhwzeOJaTm-Ds0MezeC4U6nVGyyDHb4CUA3ml2tzt4yLrqGYMT7XbADSvuWYADHw79OFjEi4T3s3tJymhaBvy1ulv8M',
    qi: 'wSbXte9PcPtr788e713KHQ4waE26CzoXx-JNOgN0iqJMN6C4_XJEX-cSvCZDf4rh7xpXN6SGLVd5ibIyDJi7bbi5EQ5AXjazPbLBjRthcGXsIuZ3AtQyR0CEWNSdM7EyM5TRdyZQ9kftfz9nI03guW3iKKASETqX2vh0Z8XRjyU',
    use: 'sig',
  }, {
    d: 'QCRapETx5p-iZ2eg7TCK9LWmIB38CZvbiDwjaDZPGM-hOvgYiD5HdsKmKyc40R6XWduAZgINQ8WfPQ2ms6Xfdnwdy7u0scy0lhDQlvWrF-FU1SQ3t4jEzI02zDZ3EeZOg3car5XpP5PRVBkC9yxmVYpQN1MRdNCwfkeeMSJtUf9LwVZXdfkk6VN0i_FjXH77cDhoPk4WEayWWSKLNeq1Hu9bhkXwakDoveHtpdgVoWR6H8RVZcIndzFS-tKxRUkUum6cr4V9zrcH7vI28W9M0LT2EU5omrs0MNIBjBzsxH_osYOol0EawTPIjejhnQSM6akQlKWzQEv6iPXKvHF5',
    dp: 'qNx5nc47pEfF_hfn72Xh3Tn_cQFIC-3dsWUQkZt9P7ve4Ue30S-sICXb9sEaeJ3oF2G_jGW6sLu9o7pkyKBQnaoBbZrDfCrPqF_5wFkR14SSV6PteFCMuooGeyrC5RNnoziFAX0roV8mpIyUlr1_NuItMqIBcKprvIUaCPQbaGs',
    dq: 'HUUQCZO4Xqe-0tknlk0RUzqFOKvdHTmMeAAKb74_aG5R9_YmfE-U_JO5SwSzer0BPfbIQ8w6NsU1MTiptW9DPkkzsZg1xjuYWvdfjsfuJUN0pq1QNxotEWna5YpZP1nXBXO68LbBU84KU7RMgOd8mSGI9zANoCOPgEzWP5FiY-k',
    e: 'AQAB',
    kty: 'RSA',
    n: 'mXauIvyeUFA74P2vcmgAWSCMw6CP6-MJ6EvFuRARfLLJEi49AzQvJl_4pwDvLkZcCqS7OqPE1ufNyDH6oQPEc7JuukHMY02EgwqHjJ6GG6FQqJuiWlKB_l-7c9y9r4bh4r58xdZc6T5dFVSNT2VcIVoSjq9VmzwpaTKCUyVeZYHZhnLfWMm9rKU5WSz75siG-_jbudItsfhEwA59kvi4So2IV9TxHwW50i4IcTB1gXwG1olNgiX3-Mq1Iw5VGPzMo2hQXI3q1y-ZjhSwhvG5dje9J8htBEWdVYk4f6cv19IE9gEx7T-2vIVw5FCpAmmfFuRebec49c7zjfr0EyTI4w',
    p: '65DqEX3ClDSQnH2mGDcnOWgy2M66bNqGA8DSPxHiNc_alLPD_3PJh0Q4PVIZeqi5LBxaHtEl28EFCaPP_2rfM22Ki32jY8WVSdoCMT5sD8tOGCF24zChGLHTRKlq1N7xffiUUUrzFTJE8_23r1GoGxRU4b81eiIU7iLxjepYv88',
    q: 'psaPv_vFHchNJ-225VnGwvfGYYKCoNgFBSFlLO4KvjPHVwcLDLuFlw1DJMS361s1cDhngglNvl-dgATfav0fJlYiVoh3Q0qHjsAW7Zq07nPeN4IW-n0tWcLBccLPj-S4oNiGWmax2IvpEdHMkY-AhpGbgOQEz9FXYLyHa6vStq0',
    qi: 'bqrEvOsv-dzuhh6dbQfxxq6aQn_hnYi89pFcThfkCEQmHEFqOoxR121QlqQmVPoZoqN7kzxvf_qFEyjvW9I-JuUlz4CbknhwHQrniUf3YwFtJ3SouqmAEL01c5pcB52Bh40J_xmd-Z7whjnwNMCDPQXTEtQZh4BXh4TWrq1N4No',
    use: 'enc',
  }, {
    crv: 'P-256',
    d: 'K9xfPv773dZR22TVUB80xouzdF7qCg5cWjPjkHyv7Ws',
    kty: 'EC',
    use: 'sig',
    x: 'FWZ9rSkLt6Dx9E3pxLybhdM6xgR5obGsj5_pqmnz5J4',
    y: '_n8G69C-A2Xl4xUW2lF0i8ZGZnk_KPYrhv4GbTGu5G4',
  }, {
    crv: 'P-256',
    d: '6UGMJFS2Zew2mcW99l6orWmkgE1Oqhib0NgAbmMuSqs',
    kty: 'EC',
    use: 'enc',
    x: 'Eb3RtGgBGOEz33yu46aha_RU6pyBaYNlu6SawlWGGHQ',
    y: 'tUncttzF6Ud4Abfn1N2A1Rz2MBbJSdI0zuKS28BNb-U',
  }, {
    crv: 'P-384',
    d: 'nHHV7KHGMNp1P7fIiC3iSNUb07pzgcjNgumLhy2nGYCeNticodVEOve1DQEGkVtJ',
    kty: 'EC',
    use: 'sig',
    x: 'P1npwyTJ2p20D9_r2u31DU7tfDEufaVcSJJcDOuO6QyqrXvjyMvf8e5xv3XxE39l',
    y: 'tmq2S12MVdKUQTmd0AxVEOji1ihR_vZAhTLKojD2XW_2EJH7ydiaz2oxrnkC0mvI',
  }, {
    crv: 'P-384',
    d: 'EG4BxmopR7AlnqcwkpxR1n9_3Y3xxWCo713eDMINQDcgmyleIrTyfbghQ_NNwiuJ',
    kty: 'EC',
    use: 'enc',
    x: 'UhkqvxbxMCGtkg_-6W0gqkr21fgY3LSaNbquU7CYEDwBwGCd6iK6Bu5PVUxraulY',
    y: 'CXrg3mxUkN5D4bPfiLfnD1jMYGSDxn2Zeh-8_OOstX21WNZJ9_i-iFZR3pIXyH0z',
  }, {
    crv: 'P-521',
    d: 'AAoiKdycjZPhljm5_HxfQHfo0dyytkqHB2orRG_f-JqMTEywZ2uupPfVhXWS3ub6svhP67eVUxBY61by2b6R_-n_',
    kty: 'EC',
    use: 'sig',
    x: 'AIjEl5H8w2Rf_iqIP8WT7v5-FlBlBGYy5sMJs1XOxWz4RRARIEOemEY45g10sEPzZ4qe7oyjCUDK5FY1WwjRvgHK',
    y: 'AaKN94cn1ApvvfpOWO9VpJm-lLzOUR8XxOrKYfPqcLs0zEqSPiGdWA5CoNL5ck1q-CXD09ysQSmNkzFGaig2Mnop',
  }, {
    crv: 'P-521',
    d: 'AQ70oUmOX1XY8Dzyy4J-41O9t38R7w8vc0NAwwaJWFnzOcBZ9i_vxCVMKh7nA3HzNnfwhgCGw7iFzkt7nlwDn7OJ',
    kty: 'EC',
    use: 'enc',
    x: 'AXFcu6lqcxoyFUU14xTw0I5cfCR2q0jqOXwU_EKjA5mIxUpue58IIrfrIh4IauV3co2SziD6Uf1SWe8l11Y4-BoJ',
    y: 'AREzsMJu3VveUPMaJ2QWmjucwzZH4FqufXzS2IW-MGqViyDNTg2BgX-2VCJvdTo0zbhvRvBC1ghJNrVnH5M92JQ6',
  }, {
    crv: 'Ed25519',
    d: 'vxd-I9I5Tl76C2q7wkKteBqM0fYLa0Ev6C6CqjfFP5Q',
    kty: 'OKP',
    use: 'sig',
    x: 'lDkysGJKRmJeUp8ncTyGraHPHHiIfdxSajxGm7Srla8',
  }, {
    crv: 'X25519',
    d: '2FxH51AcogWa_0iVjUngdfu-HBXXt7qdAeqUKLbRwnA',
    kty: 'OKP',
    use: 'enc',
    x: 'k78x74A5JRGr8XW75Rpu7W4_cgZFkm_mvToVAXHDgE8',
  },
];

if (SubtleCrypto.supports?.('importKey', 'ML-DSA-44')) {
  keys.push({
    alg: 'ML-DSA-44',
    kty: 'AKP',
    priv: 'CVAVuNIaH70i8Q6j0hFtBbgrMrSY4Fvmi9YxL6Mq9fA',
    pub: 'jLeVBdnK0cnl1umUSe1HXdapKrCY1X2seFG1HjdnWmR4FtfG_Xzgohn2Ae7zIGiaFVSuyRetMUqTtV10u-jwSRPx1PBK1NXJRC9xPdY-BuGk6gkz8122JPQje16PM2Mr0JntuLRSiYslu062oDJbsR6pThJUUXOva0lfZl2Pa6oKgQpQ_gWi0um-nw_U_VRLeW2-u6mLAzRLW8jETOUdwtgJ5QZE1dWzHgG4tS9re_hRNwnuAjfptq1LTiAJxFgu45I1jVgKkDeNoroc6jU103-QYjqMIRWVSXcuGQg_cKZ1R_tH1VwZ1jvkkwlW4wlQrjcLJUq3dNHA2qXApQ60b2kUK7xe3TW3FP45GzGrUfHFCrY0GBkBP3gZaj4gWHzzPOP9zCEpPI6_QPbV8fFcfw5iEStJNxmKZqz0mLAPKB00yKGOq_4DSSUjJc6hm2_Py_gz1psJqK5h2S1R-uGSubI3LA62DMih6WpTcm2WaCzWJ4r-HLg1MWeuS8WMCi0rUuta9WpUntm0zxDAJbSZ2Ln_LdpOQV9BhZ9Bk26L-ci9qnJXCwsRkFFcL0zc-55l83clERZM0YO9j-ZH_-vjWJ-NeJx0QOgwR5d0l6joQPSLZ958HOXX4Lj_HgrxObPmnvJes0C3ioe0iKsG0vmzInep-PHQzXtbDqrPk7JitNb0MXa3ZAMQJRMEsVT-nobAM565nZIjwY5swOY-zudM_X3IlDaDAJ6hwuqAAV4MmF_PNjWLcTakcvolYfEWYuLiPjsWFMlur4dfJsi3rPyzuxosuSI9NRuuVNcX50C5pIDbBvThfxwZRYH-j5LdlY26uWyfuDpgzmMIHcB3hnyBcpksdpLojnepmIC7i5gQRAPSSnIN71bT3hI1ph_mIOBCKvwF5nYrnaGl0xe_YBlpwrZQMglAoUVVIjc-PioYdm-OYn3mXjyaLlaEVQPHiNdx7WWkPNesAbb6c27cwW_1dcHeVt_CkUIdlQe9K2rveg-dTywuexByP_R1a66rKYwwJ2Ol_fO7H9QAHbrhPuljge5aTXgitdnZSNFGbklGDAfLVOwQoCVVQg8IYbPSSzafWl4fhsCmwkjk-CeT-iPcVK3TYfgBufQ9N1BUJd7Jv9bo6NOwKRVUrQgj7KhvfafxQejjG2e0GNeWxdGIFzvjdo21kFnja7swIXGGtG1bX0-ZwkRujIv36AbJmsv0ALM90szeHIcSlegACyHpuC9h6xFmqpdcwGN-deERCGyqQrCZIcoSM6FwJ4sUJUqDSfutqI5ydVJnfLmiL6qo4Nt-QW8wHHrZu1t0AIBYMxPUtXv9yBwHHhcdhaOQo6SvRCUnuvi7jsZsXVm4nj1vl4-IxQ_Owb1l1KI9LfI47GZkgn_aLd1jju3cHWavD7FV8n9MRwqp5nPl4BOIzZiqx9c7ZtLIOYScKLRY4JpbaxYziTRi68KQ839yrePLxyE8IRjRLaas6-6urnj1wX_OmRRO2JJ3NubGZjOPryZwZBafn4PXjIGjbqT28qAWMbjpvxvDCu-zukZyGzkTgRj4IIbvElS0gtaNyLM7DthEgasnebwGPduJNLMt4aO56pUlRLRL2OvblEmmmA9ucLG4W-YCaQwDZUnaRIjV7rvvXkqix3Jh8FLECd04-n90o8bohhjcCuVmMGENwKefVdDRbni-EHfWHDnoF9K7dEkh-6QnzpVWcQdD0Lo_FAzel8JUy_Uwip2t9USwMUPac8ENAnvSQA',
  });
}

if (SubtleCrypto.supports?.('importKey', 'ML-DSA-65')) {
  keys.push({
    alg: 'ML-DSA-65',
    kty: 'AKP',
    priv: 'JmvgICpvNUA0n1OAqqt6yldxHkQKOsVVTMnSNHUQV7c',
    pub: 'giq4EVVjvdH1ehO8KrwbB50zpsMcmPNQfj-rvFTCciVJpZY55SGnOwydpGqtVSZtIeEel85kEBu9HsM85KWonJVbQ5udSySKR-kIsfSEyD4Y4bOuIbrPi729Pj_tUregTmYyySCYvsoY4xZ5qrhiaigBQwap3lOf1TS2MGzWc6OT1YAX3ir5PKlCOOIUi9z7WLCN3HlmPuu5BIWog9DHwOED_JFo9zyufdBs9TE7xwl-vmef9oMJ-lRTpYnAMTHQAW7bnbeUtqhuPmLHd3oG-D98qXXHJSVS_Sws8kw6Djs9g3u_LTScahtISEWP2akhkDQgiUFadMEqOsOcVJPesbbseSuj-3vUCc7ahT700KNmr26GAvUCG3WBUzpCKpzp1IVu-NSjvMN9SGhdDNMaqPNNgPKf5D-5syti8iF4hm0T4ymBxtQJwINlMBvU_KaQ4lCJ8Z68TaN5cpjpFrLhoDXYc0ymGNo6KCfRzWTLnls8xkLWRN5ATvtzGN8nciONQy6Pewix0TA3m0ZH9jpgzQa0Hwx65DnMr4322JW-FBtTSM8gcczs9mZ54jgv6y0uML7DBOciEPjWvyDg6GuUq4XMeRpCfB9wl8S-8dNf5aXz7arUVFdmJ7qyYcpQD0YLlSu5QLlygyTxhW8iQCAOLJ0jug9Twb5CTiXj4SyMTQMcL6E6haEIfrq5H_10B53-zf6xOoL4_ctF3F9zT4sjMZSLayrkRQQ8arDORuTyggZ3Z5cbAQ9uusHjQmKj9nT70Q4Hykszt_vsOjfKo43gZHq_NsDwatylSmYlk9NdSTDJqm7dxGfJO4CGqm67nrFJguwNt2x3ANxNHlRCbmx8V2G-OuWIIvJXzYvdVWDW7OxNebAJFjVv0CD8FvF8YTSmr8KzJPVgzp3x_p-4h3vhrofS5KAoZQOBTD8AZrk4mQWiGE0m2KpSQdty8CDuTqVMK_m5LNGZBduMT4BLHIqIqh36ZbncA4ZUCNgMb355i2ee2pjwAd_qepageA3WenUPdk_7aNOwyTyhRfIohV4BD5JEieXrUUxKOGjhDJd6eIb4VKanF3AS436GDBSZsdFR5KRNwWm-PJ8cGO6DuiUdI4fF8lsi2d_RatUQtaRBz8TNKQmyJeyJxq9jya5bTXVP6EjJPkdGrnJ7nAVGKzant9GYTyToiZUY6yUKS6PEoWxfhrG0pdKXwDZcih7fzfxeZBt3jj-LbfBFtOvpKiXU5ZlOtaSfScmUl4RtBng-8LWt0Ni03DV9o0cLB3UM9V3zsmC-kXSNyvARkKylFnMGuY7ZQvrCMmO_JXebJgMg4UpcZDYEJT3GtaGpZDTgfcbPovIUE5E2GC3EqyjEtNobZ7Kq8UsUH3AMsQs34TmdYDqiVr47eGljXDASjA5knB-oZJmMDjgBmZDJCM8a2Dk3qwYDxHYNOd8mwdusT77PB1aFhoS0Xomg9pl7KCf8qxndjmNdWSt1TFfuUPx8XdV4HK_u9BCvnVQFm0UQvJBD_FG9WfXxQtr4UpyKPwnTrE4ejzgwR-8CiLiy66iBtGHzpQN2IXfxSjowWp8yodwk-JXEn12sDyMqpNSTFolgpvA7HJwUGNuM5OMrp6XueKvEcLhXcT8rccHdomeFG14IPXBP7NtZ7VWWoDTHadjIs2zqIeLvtauY6wxLKMjnf95iuF1yyZzSo1MUM7uk5oU6d5roFLGXUu7XnqSsD4CGRLOBp66t5d__hKJM9zt1DnjHWBLp8kVoar3i4PfRgWptY3jhelUFzr6YzLSZOQeahefRe2sYgLSDGpw_dWxIZa9ezIyYt3jnWZjeiI_yqSLNPqlMNw4PDfq0i28RYD3NMyNsezKkXqthR6s3VOqeVRiikA4vV2V0XPnCPgA7dlVvv-YnrXO2k-aVQp6W1Eet8wW7rava_A0B4YP845R1hylS-1ilT540VexYBDgWoM1CV7TcjgF7CNaJraB5s1dqoDg27fWewHrKBQ9aWer5H-e6hZZ-7cuhkH-2KVLRh3BCvjhwhfdfNo2zev0Gugtyhf0jhpQvQOcC4NeKBfZB5piv01eVmhaHEilmck9_HWg5J3mBXFRbr-UM38hypCY_eSAYULK2EKqeuJtlvar3UXzhxWtkPueqUi8Qj5FWDJlN7VpzuGBSz8ppkWLLr0YhyV9fgCUDh17Oh-qRt13Y0bkRMSQKuq7t9pQ8Lg3HhqaR2zdYs_XdAinkrXQ53nlNhDKHiqd61yGv3UKPc79AMsiE7OU7rPiNE-iJyAiKcNP25CKHUpcRW54b_ZvC-HJ8vHVgQemmtL9y9b43FJR9VVomcMRo1BQbwLefOAtTJVoRmbZT5kF4da9Brt26uJBf_PVNoFUd2GtRKjTabUyq5YaFY6fIy6LTB9pqaNa7riThnsVLjaHLb3GoMxPphWedgaW93wzeIqDKP8p91TV7u3Xy8DFUGrjLO0Xlqu7uXhZY36kh9qMOvt2g4txCmsZHTWiiXIv6TL45plJhSR7o5ZoHjHBpVLA5RCTV2ELuLEidAgdoEJU5hDtIjPiBaCTz8uqsCy5IZMCjctZajJRMGecB5ocmTcbKiPyodw1MDeo1-gc',
  });
}

if (SubtleCrypto.supports?.('importKey', 'ML-DSA-87')) {
  keys.push({
    alg: 'ML-DSA-87',
    kty: 'AKP',
    priv: 'XFfHGpZozZzyKmbGk8dk351FtaswEwF8k_LxLrD1fOo',
    pub: 'FZ4Bf2Qp6mdD6xBcbhEFWpOQDBdn8bkLl2qWHKArKF2pTJ2wAx4UPjdUDYj0gS7H9_ljP3AfthLGD0Zvrfi8P5EZiadlBEZqIqfaaZ31XF4Druqjo1C0ugUZQ_RdJBLPpfe6CFwe4zLrYrAp5znSn93VUjc23puznaqFiu_V3c40OAmka19CJyoixULFdc_2pMq0xFivNmIKLdfWRmFFJL4g4mOPOMI1gz-iS3CHGltyJ6G8S82mYD4h1rXUtSOTLuIp8mH43ibVQiESJL2det-MLEJnxLHiUOdNCr2BvCA9FtRkkR8eOLMNdSftkX3_olYyR0xoUFrPTFFvJiKYiCIPHSIGiSTDAvk3vrOJO4tpj1M0f-lHqSkah_zJQiQTuLkfGl-6BrUpzGYpKTOC6qT0GEHrueWUYbnftMcnTgpFG0_l0mupfthlravd4GJop3Y859tq39-c0aXcv-YqYBM2_SuDLebzI1A9wNmPYQlKXDkd4uzO4QvYvLSyaTR5LY902F4RHivcbklvKkmRcWYf-vKxcmv2Rf1U5Dl7hJGTNtA7MQV3XIQhRQ01AXqT_gOvwZ87yr0lEddZdhRAccjG8ys1ZD6ZUTxiJsE5XfSa3Rc2jX3yBBwiFMvtqnsstL6rTOApbpGY8r7DYwBdDYVJPBUHF0Y0vQjeDJiBD-REnSfwLVZuZDo6ttAKBZ16Ev1WcvNhlaefvI37MdOTI_YgxsY9_J5SxgVT13s2Co-65NLtAsCVp5siEQ7JhyXJ9nz-kfqB8Adpd6GRR8-tsAKi8yxEMGQEDERQ-afdAOqMiGIR81HxgogDvTNRgXtxp86a1fBxKaXIQ5HNZ6SChaFoL2peXruevb0fA7v1M9bIw291hkqjs9qn4yWp53aNAcBKGkwvdadt_EJIufFI-F5HKQBtf3rmYayUs240mQR13KCmyxRvbxXDQOLcHqjUQ1xYvgl4V-nLhpJWDZYeaDBHMmL45MG3809aR4rX30Ht0jWOJ8eyp9GWw-m0hPPf-VKDsDV4ExYN3pPbhb6vh3zMTmRRz802YGYesbX2LnT3omYKLJqErVuiANM5moGToEAMfKtGJorC1KaFeNhcI0ueALyJSlOtDjS-CwVdks9exECz_x0JGqB0D0l6ffmV0fKRDknzK8aS_ut08OOkps1d55IiElKqsSKn92Y1TC8yrgke8w2TNKuLf4MFiZ-_JfQKobxIAGYQ3ewmO5WtupSkzXMkXUhg9o1HTHk8IQSXm0GQezQ_QUP3-Nd5I_c9YjMegKfkgSiVPUUCSc7WDMJ9tGyVcToq1xYeTie12ys-E1DMQmJQj1eerSxVuW4GkWxe5aGLSXaFtg4kYwFNwItp3AcZHz9dc3EBmhKTgIVxDrX1p1_vB88lCWnt8UFeChK2IW0jHboZLamQgUkwH4z1nUFfaeatyFFFMxojSyrSVeaPekDTvgZnzEqZTLDw0Ye1LYgwj0mD4FtqzuDODmR1FKDAjFXHirP2BsUG_lBOuIspHAmpvYuw6l2pRgyd9ooYFOgSNN7W-jSbZgyQAyqHmUau4MKtUoXllkvZkDUwovyHEs24kjOeoFQYVBR72rTbIVsRuZPz2UuXvEBqClKqWJbHhwMoG_UYcyPzzFE-pNcUldtv1i7xGaqZSKOPra0b3vD7_lkpuiC0l6uTvVbmhCxcJLIuMxKL_R5Mvxj1N1jxsgzzPTyOoA6Lk4d_teVnkb7m3BMhxTFmR-syj_8H34y2_1rtTFFW6CigKhvyQOxDJV1UZuMpg2zqOSY52gv-FpILTLNWQiUTVVxyC4KBhbi-NUepsYe-yFTPnWd_NtITFzkfDfZ3cP2fnZomJzvKFEyoUgt00J-SFrHzCFCRHZkbTegjTw4ar6OtF6Z1Wo3TmlpxLeio5j0XaaUuJQoavAoC8ocWBbq3Sc-RybGiNSLQr9eMHtBylmByn1XPFRv60wGGf9roV_A3o2n8omFA4xnoRf95XxH_kp9ZDCoTY12utxf5zpuNmnitd4kpeDdpmUlNZsjhEPDEp9aQsCbYKXA8CeOM6lsHT92YZcGq3e-LlvK88kzJCBxIbcJBXGqFepJxD3NwmjBPaOgafnE8ji_Z670_vrZ4G0g80q7bKDr0HkcIt9vNh8Lr1C42IiedvbgdihDKcRS6LZEWYx-0AlmeNIwgKN2wq4NOq0SZNNKfOzXVkykicgaNv0m_ithTGme6TepATvvNAVm424sKO7JFfXQSGRXauAeONHRZvwLRisofVHk0HhOHiwWVDvGLpaz3tYpQArdwk2nPJhYtzcHU6zffr1YEYeftejzTSIXUcUCcdepcH_uWlB19AzLz1jyB0IRzMVCmf9VVB1HbqrC4UfkxJ1FKbddBDBovnNBp84Q9tgZDh1ePX6FFc94lIXBbALenBlCJJYAnzJtbjOlF8UEJnD-ub_lGTi9Jj2h_anUT_YEur_CX2S90KHtGIC16wXEhK93ctbDnicCACNStR4I73WEBOvAHErXOh1yHFoKyeXI_9j6D_5wbUXgsQwD1dQk5n_aVuYcxXLAYJA48i1aP6K55QTdymblqmMjWgwiXtg6wtQDU04sJCfzIcpNGec03TjgnZiB5bfoyiqwBQRsTKE_912C3X80qBqOVvdG7BDpIx17TxCzJz8bP4EINJNDLxeBQbifOEAHd3JDfQwPbA6ig58mxbUWN0wuYd5eS1ChZI2mbSykdyEhVweHDd6QBu-zA-KFtlUbesrpV0kvZ7a8oRYttolwORXcC4MZKrXRSRFGivDEJMpW05efawoZ3B4S9p0TSbSFWkJijoeSN9wmaQseFMIgU7a-mbzVsIHwi-tCJkv1hn_e-_9iUZJ4GwDEDwDiZWp81xGSNbpCc2y_VSHTlZQ20SaatF2fpEeLj-zkiQXTL5eYalh2oL6CTV4c5XSVTtZkq30HZwrNxR-AxCBvTP_07iGRsM_I3ZTeVoX-1sIFgtO9G3_MVvfh7CGM57f3M7-zX60_3Mk2xml-qrdAt-xcDOogGfbuxDQMKPnVAuSw-gz4VaRU8GwLiH65zGhe21ffjU2VGstNAHnnx3pvjxdufRd3eZKH6RfOhIl8S4KdWB5NJ24fMjlCBhDbCtPSYIpaTsPlNKS5Q72uaukPWHL6JAsqyz26u8qvbkSn4Lu3v1EipnmZ7PUnHg0WKkyPetrWCNjJpviSwObzfZXFmVhpWDVgfNbnBJbwed4aNtl5XsKDOTu4er24u5sCTYaScwS9siuUGjtGHwTxB8JaO_OjAy0RQi6_dpstt6CQFAkEn0l7Ywim7KWk7oyASD-PB5tVV6y_0i78hfXOFtSA0j_f_Quw9oLkBnF4MX7F-iHC-R6pKXNLFjgvCMYNu5AaHsQ_aGBQNXtV4d0XchA79snVP_IqsKfPoiOu9EqI4HXwypmG0uN_AhKdpaXzOLTVB',
  });
}

export default {
  interactions: {
    url(ctx, interaction) {
      return `/interaction/${interaction.uid}`;
    },
  },
  acrValues: ['urn:mace:incommon:iap:bronze'],
  discovery: {
    service_documentation: pkg.homepage,
    version: [
      pkg.version,
      process.env.HEROKU_SLUG_COMMIT ? process.env.HEROKU_SLUG_COMMIT.slice(0, 7) : undefined,
    ].filter(Boolean).join('-'),
  },
  claims: {
    amr: null,
    address: ['address'],
    email: ['email', 'email_verified'],
    phone: ['phone_number', 'phone_number_verified'],
    profile: ['birthdate', 'family_name', 'gender', 'given_name', 'locale', 'middle_name', 'name',
      'nickname', 'picture', 'preferred_username', 'profile', 'updated_at', 'website', 'zoneinfo'],
  },
  features: {
    backchannelLogout: { enabled: true },
    devInteractions: { enabled: false },
    mTLS: {
      enabled: true,
      certificateBoundAccessTokens: true,
      selfSignedTlsClientAuth: true,
      getCertificate(ctx) {
        try {
          return new crypto.X509Certificate(Buffer.from(ctx.get('client-certificate'), 'base64'));
        } catch {
          return undefined;
        }
      },
    },
    claimsParameter: { enabled: true },
    deviceFlow: { enabled: true },
    dPoP: {
      enabled: true,
      nonceSecret: crypto.randomBytes(32),
    },
    encryption: { enabled: true },
    jwtUserinfo: { enabled: true },
    introspection: { enabled: true },
    registration: { enabled: true },
    registrationManagement: { enabled: true, rotateRegistrationAccessToken: true },
    jwtResponseModes: { enabled: true },
    pushedAuthorizationRequests: { enabled: true },
    requestObjects: {
      enabled: true,
    },
    revocation: { enabled: true },
  },
  jwks: { keys },
  responseTypes: ['code id_token token', 'code id_token', 'code token', 'code', 'id_token token', 'id_token', 'none'],
  subjectTypes: ['public', 'pairwise'],
  pairwiseIdentifier(ctx, accountId, { sectorIdentifier }) {
    return crypto.createHash('sha256')
      .update(sectorIdentifier)
      .update(accountId)
      .update('da1c442b365b563dfc121f285a11eedee5bbff7110d55c88')
      .digest('hex');
  },
  ttl: {
    RegistrationAccessToken: 1 * 24 * 60 * 60,
  },
  clientAuthMethods,
  async issueRefreshToken(ctx, client, code) {
    if (!client.grantTypeAllowed('refresh_token')) {
      return false;
    }

    return code.scopes.has('offline_access') || (client.applicationType === 'web' && client.clientAuthMethod === 'none');
  },
  enabledJWA,
  pkce: {
    required: () => false,
  },
};
