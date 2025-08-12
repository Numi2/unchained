# unchained

Post‑quantum blockchain implementation - Dilithium3 for signatures, Kyber768 for stealth receiving, BLAKE3 for hashing, Argon2id for PoW. libp2p over QUIC does the gossip (libp2p prefer pq aws). 


Unchained, a permissionless blockchain that couples memory-hard proof-of-work with post-quantum (PQ) cryptography and an epoch-first issuance model. Time is divided into fixed-length epochs; miners submit coin candidates throughout an epoch using Argon2id. At the epoch boundary, the network finalizes an anchor that commits to up to N selected coins via a Merkle root, enabling independent verification and efficient synchronization. Ownership is tracked with Dilithium3 signatures; receivers obtain privacy via Kyber768-based stealth receiving with one-time keys. Unchained uses libp2p over QUIC for gossip

- Memory‑hard PoW  Argon2id; memory target retunes across epochs
- End‑to‑end PQ: Dilithium3 signatures, Kyber768 for stealth, BLAKE3 everywhere
- Spends don’t shout who you are: one‑time keys and blinded nullifiers (V2)
- rocksdb

Nullifiers (double‑spend protection):
- v1 (legacy): BLAKE3("nullifier_v1" || coin_id || sig)
- v2 (current): BLAKE3("nullifier_v2" || spend_sk || coin_id)

## Quick start


```bash
cargo build --release
cargo run --release --bin unchained mine
```

What happens on first run:
- A wallet is created and encrypted with your passphrase
- A persistent P2P identity is generated (`peer_identity.key`)
- The node syncs, then starts mining (if enabled in `config.toml`)

Stop with Ctrl+C.

### Show your Peer ID (for peering/firewall rules)

```bash
cargo run --release --bin unchained -- peer-id
```

If `net.public_ip` is set in `config.toml`, you’ll also see your full multiaddr for others to dial.

## CLI (no surprises)

All commands accept `--config <path>` (default `config.toml`) and `--quiet-net`.

- `mine` — start mining immediately (overrides `mining.enabled`)
- `peer-id` — print local libp2p Peer ID (and multiaddr if `net.public_ip` is set)
- `stealth-address` — print your stealth receiving address (base64-url)
- `proof --coin-id <HEX>` — request and verify a Merkle proof for a coin
- `proof-server [--bind HOST:PORT]` — HTTPS server that returns proofs
- `send --stealth <ADDRESS> --amount <N>` — send to a stealth address
- `balance` — show wallet balance + address
- `history` — print simple tx history

Examples:

```bash
# Send 1 coin to a recipient’s stealth address (base64‑url string)
cargo run --release --bin unchained send --stealth <STEALTH_ADDR> --amount 1

EXAMPLE: cargo run --release --bin unchained send --stealth AcF2IFUht7MmqoHuo8Nf6LOGG94d2za-gI5aG1R50r-JoAcAAAAAAACgGlNhdFfE70GlPMN2mrSWhdXuEjw0sGtIDOIaLBYMhfC3EgfgJ0jS_Eo_Wc-2j9QImADGwMSj5Par0rWcLrksVm_SSxdSnWNVOgCFNEf0GS2AOcggGZSQkVajSEta58a8twogTkm99ZVqHQoxpQ35tC0g6x0NQb6YM246pJ5hI_cub9MhdqrMuESLUlbmq0cvgZlGrCXW3dqCmJzgkgfqnXNAPR8W-32nCYGVELOPdx1tEZSiJdzU5DAc0ulS262hgvvnh6DgHIrYYWmv2yz5Jj83d-BfV-99OKeyWku6NnmPqCdjrvdssmq7szreHGVJaxNOF1in8PTDFqEBDkgwOpGns__VNpjWdYLvkC6SPkzaWfN5V1s_FekIQrRS_WZqPUS2QKzdhWe9RuAHohR79mv5ofoLwUiwpqe-TLervy7mkuB2GBJBS8zud94G64821cmgTOvZfVIjqk5ZVfssfUaCzzkX7mWfKIXFH7q0OYIxMsEgsIyhbo4Tk7lRtJ04A_nWrfq05RhI3I1hPRX9GzUDBeNuRQEAvFmwJf6jTshCc-tOiLNV1690A4fuT2lUcq_jwFa2flSKKdpWeU7fLvxlbz9iJ6XwUulBdZZU7Oj1mCVb1tNS7wLy410C26WtuUSJVsGWpTflfPyusAQTG-1LlhqBxrQbkjf-r49YTy4CypxfLNKY0G4QgrfQHEOXrGb7qBfsp6pcRxHnhR5vQCHxy5krN0XFb1SFx0MjNQbBVCAhp3PxS0abnHNvznOCeMCsSiHsMJ4HHpJlDnzpFYvRW6eH_cb3_pWsRFbkyA2cJombAhbtKZ6NIyavqo3gpqmKEWIZ52ZQ4aIjdAFx1Omw9e0abI463nkhfJxrrL9rkysPYDMczYGtalI87OCgYyMvkPxryxVXZ8J9WIkID2gZ6qGklOIdmeiCxbzV2gc5FFvdYVlvupFIRv7KKbazRBoN7g98UajP2vg8WBgkGvrpJ2Y0gY0-Gg7WeMtrwLryfnCuDWuh0o1VtbAU-pbgbRoEgx91-oJM95oeY3C3c-QmaJsTuRCIOjv19gCAYV3FSyKHrGwnHLZv4opgKrPCKhlbwPm_1URP60xUsFgxfYiq-tk7_HbWTPdudDXPvNz-Ziz9UAxlfsA7zeTmPUBeB6zXFbjld2Dx_U7rhJktqpjtcsvUCRguru244v1F4l8BznHbekKvzTGB7b6o0MZ18kbiEXnXPNciCWF78aRCy453WpYPMVxiob71l0_5PWaCzfULxxeKW6wW47uyO7YV8svwB-TLP5gJQIEny-3MpMNiNRdsKRYKtjPIC6J34KCq4f1vYCKzEvePIeUJ9F-v_t9dgl8S4eiu6gKhBmUbL2C_plrqI1lQl9d6vceOpPbbrIylRniaiZfiROB6U17rgCt2qUp3uwFipA6cCI2kv2zi8HbW62hquxE_lYNEKTf_58TjbNGi5dumRLRSihTBjVVDinVfI0YqJseClj-yonK2bB6-F9yHC1MNHqBSmkF_JijcAlRZrXEkskrRNLDes-ORRIFYNIYr3xZYcHH-LHEj3TAexerBEYyCEMQLSn6i98Ge0SK7FO7XwY1eqRgkrH1kt9Iy4xLKh9wReS3BKZG6c_AzDW6PW5ffZrTU_lemFBTE3bOrFamTVMQxqn52K2S_LXAJJinRrkzLBtFIRWq3SnRJKNF9HqonS2js5yX7VDhmFzWDxWry6-RW6MofE3yPFxhNb475l7hny18y5EOmsMLliwcN4P5rGy_-NmZcwIgq_fhLAGTVJL_DCmK9MkUHqezr1XIrqI65R3WsYjPyuXVuDsVloCBikXzomaorP1q7Md0_VrAhHAMkRfgU6iwVvHhW8NkfzswdEqpzH3lyhTHgLSfPTBBV_1tGTpBXdqKdbwrRuKKJiCf9bwGEjxfwRHlKtCgXVFM_uDlWHcx_BMrktPvDd8S7aGV6CDeZNVMKkmMJ1-rvuxKOFWAg0_flBAv8SP6pXe7BT_rzYX2y83nQT6zA86G0zVjj6-JFvteQnl0SlM6j3ssyviRXXpsO_jca75tXcxqVkwW9IO6cWv8Jnl_giO95OjkLujtvXRLJDX5xOq4gxR_BfTLcLxgWeItHuL725w1WGqidkYd4kzMZ70OqyBvwHZtcqvBu2vV2Ng9pVyIwj7qttYPFAdVTlxGjbBiwofgAar9iQ8oVPHagDcqz-a119Ok3rGRK0xIsFjtKaqCpgXwQlp2TKnopoUIpA5xC-Pc--vrR31ePkjxxOzQrVX47_kBd9Nq_H31g-x27Ohq5r-pWPkpWnqDwCOmz1yjy6ChSkIm3OL7pHKPcH5PG3YiSkTTETO9lLs23uB9bLz6lOGScOcLVd1IIK1FUh_3Yt5CmWsoiD0tG0cLEv2IvjDiKugwOEmqlFrZhM2t2UIUbChAmE10YX1czTNs_uyAjKXYtI09IP6wmUjEL34bRuEhLEjWVpxOXsL8lfWsojb5hUF7ZYhLCrWq_6lW32oGxxD5CDNXnyVD6IH00zW6fKxIncyK_bwyKWVGoaSA4-4nB17tTf8cbkhXfywg829Ti2NqxixZJpnLuKXGOe37y18NQi1ym7KAEAAAAAAAA5mEmvsFOpuRrl3JK3JYGaWMpVklGSvgF57QIIfxiaHZEhSmRVtGX_bm0MVwWNASnZZCcF8cEnOcnKxAjcDF1o0MZs3OQDRMbukgF7yzKzAZaERUnY5CLWtIRFbPBEDaVs4ddO7eui9oD6shrBkI4MwRX9DxWO9CvAnWzfZWT8MEyTGSOtOYFjzYJIPFU5uJzPqp1YZWwrkHJvTIkE7Yr_KsBoepgcCtHrAXIILOAuBGd3Di2myYA1PaJFbVMQ9tfT4wc46jHSdy_2by-6gJuYFRigmair6hRaIPDMgZ5yhu1cuJK00wdyeSdIWw9oDEnz-kKINhEgMmARNGuUoiGruF-pWkGypEg-0eygNY_beqZR0m5LxQZH1Ux9WdeUuKzboIPWwqNHuxMV6l7tEKRlCrDCwWplYiBgFYKilNlyba-DrtWZ7fBafQwBPpjMuzCS4Kl3ReWPEOWmvkkh9IZYoqCIWcEbLegcMN_O3mPmPsKb4c4ZDDCiOQf5YU9vVcKZABdQ8fEfIHDZTxTFREuDAh8fDcZWdPDtpuQi_Eh4LJnKeWu6ya66Mo1JakkdJhU9Pc9QmhxKWpZQnkP5-oc2-ONagccksJEQ7uLe4x7iYs7KoJyU4I2SFoqdSV1faNAykwOqNICCgEGCbysP2vOkMojwexpCVlItKmVTTMh90iZ3Kw_QNcIiHhimpi-bBt89kNoMgNsFReq6CwiRXe5j_a00rsUFzGJQjDK82uAm2XORns5ADYuPTkuQGa127cxrhaRTgm71HpFr8AUaJc2nHVjwaCrjiTK2bLCsuQfToOZbwhlpftigVoqG-Q0pDiXU5IfqKTAuuoYZYe8bxVRR8lTw_N3zcI6BJcWuypxLkNesXEqlOnPf0CW02oD-srC_xcig5xIkoCdR4t-uhtb8RCHyOYxAtrIkWCEtMIMcmHF4DyKiKEeYyJ17JiGAtkZMXC7OTqwV7tFP0HDupTGSjAPyBy8jTZ4NriCIEkQ0iTNldpnSgS3Ene_ajUGJrc7A8hYmmUoltw-hAgJQvJ577FketO3UbwIfPSwu4FTfCrD4mnPcqt62XaoIucRVKKkEwo2knvDCTW0WTMpsYl2xTovq-YL4ghFFRhDWgQgwLhPWLVc-OSVOGlDuUp9ooaftmJTSUmut6PKuGRel-g3l6MjrxolqaQbl3aaVAGucFnLbVx_XPxCy2YZenVlSFRGyUACuEdwALSbfpUSoQckQSwuaacrMNWYbHmgkbafomYNSwJtQyZ12Ui8I9kKXzFz-TgcV8secJVk1dMLcjONC5TP1VEzdywvxamaKXOEPqkq-7uT_jMdzlk_3sVcDJJMCJAU4OXNV8EkBMbD_rOyr1gPyuCTANx7MFYOkWMnVroSIGlKwENMMiONkXtuiaEnnJia3FbK3_qnQYiikHSYHLSvpFtLgBnAg3VFL5Y276QSnUKetewRvPPNXcd-vGFmZxUvPDNHNitafHzP86Ng9SSx9JMr2ocC0ZaUGMQ81Vh5F7FHIWonJ4WNJexirBe74sI7_ZKYu1dKy-JOZTkiWZJykmDaASHOpJ3BRPpGA6ftDAAAAAAAALpXkhM_SkGzU7IMvpxOEvfbLk5IemhdPHl3n_csi5Hs3eCONSbcnoc6IkqWgKv5FTB14i3t3XmP6vityA_J4Feqa808LqkyMuMp48KRfmlnItRPZXDA-cMa-5QlRh3y546MmRnHu9AbPgrSdaDdjQLkphiXnVtXnN96CpoJr48OHTFG5NqfY_wHNyOm0K-4CRESqnG_TMMvLNcD_zttqGJzlWSOB3NEzZx2AIO2h_9xogPmymuML6ff9o5886N57fJp3JIRujc-InRB8KKpV1gn3XLn7ENgTxl3EVGD9g_Qmtw681qsSft83OvW9CxSpqIUpU14ab6j9776apTJps7M9DelH1q4_RiFuoZe9AW_ULLhYqUJB11vfrME7fH_vPmoK6mam8Zui-B11pkwqJgXu7hKW-TacNmXiPX52gcYNekR2Eptc78SgC5YY8679oiJdm_MpRHQHHZVN77ZwGrf1wR-GpSGUL5bMzs7x-hZuf2sSebadwaJG7B13GCoxThNMigUz4-8dhSaEDQPMJt1_zOnjKsDMt3dih4RqwrkInKvtcgsB5mjMWHwdWKrUWyOV35MI7GdlF5t4CcT9OFXMAJMRsHUWsXS0BJlXAvqUYKGGQEPnC-9eDnMeAGPSNNYqEpVXticXgY9_J-9Kw_xEg5EnlRnLJt_GIeMjIEnbySHEM5px9qNQVnH8fjjEfZ98FpPFsycS0oFNNjouaqnd-jSKj7jhZL2LAe9rRsIu9nIjTguBVMz0IR9_CwsqwbQE9NrcC0oW93PZ-UX_vC76twe0HDMJOtsVMK8oFiRJk-rTNHooVKPpgCRKfZXcK2OsRA1UeJmOTQSLHqCLOC2yBKjuiRLnruJUct2IzFqrGF5azuaYUIIhDy6AoM1lneLBChWcy_omuK_bzzPqNht-gmUrZSo-zh86Y47FGn4ScJoWG11kUbv4bSdQtBrErxv2ybwiHLbxI70zyHhG-5nVLltp0J9R5j0x_8g64932WvJEVIY6eG8aelQSX2nS6WzIFPQSo__UuaZdcBkqQin3kFOpcX2ySmpGOTX7rqiZlzPWW8_2Db3C36hF0kSK2ybB5KPQ9xRuZNv6KlNymm85bf63F9bJYYY4gy7Ug0rKBffZ2u6QkZ0CKQDMtai7S7lcHEEvbWWAXdS47f5mIj0kGJNGmnlz_Y6B3kJr6btrGnj1lhqynv7CpFIpzUFKcxWKOVMNfHXxt2HK8SzlzexQjhV5wnlMSBhZu7PjqCGDwTEbX7-NCjSNsqUt-N_UeLASjK8gnBns6yLjch8rfo8ug7JI_SNCQ83fPHrzPS2AwugPL-rv3scVpTpKG2rMuw6jehonjDCfWE2gfxytJP3SJWe8WthkNROtgYAeKgA4oJtGWS0NPlVN2qwJgWvBSZFEkrD1hBFs1IeuTjoUIMt9NEY2DMo-gHl6u_v4bW-jkqdmb4oifd6oJGHIRTjxLaScO-LZRT51nHlz7haAUo2x0_jIhA7be7Iap6eAH5MJkoOVBd1WNqMwqdRoLxJjd4kcvzR4mLw-iIF3fiYzRUKmMtfldEZ4-fHB11u3zoPHgUexEk_JNIYixfLQJGqcsSTADpMibI4cnVQvHc2r0_AhaHUhm2VQe9zajDW5c08pdq8-DtWfAwRKPM2_FbhMyoveB194wK0TiP3yAE9UxMMvvwgkVvkSbYV_xkBs8R6voOl64P0NemCqEGLBRvnPjadgXLPGj6Q9mvD04k4s06cRFAcIqQH4ew4EkH5KGpuVAoRrNnSDEKYBmKn0wZTDccv1SLrfVAxunxn3yHaL_qwn7fc1rZxGq7Q6Nw7ddXjRo-VNJqL5Z0uOpnmYK5Nf--1KIzedLJaq9xFmsxQ3nEyGiDTfxN485SHN2-VqeuCZJ1SuxZJLAHQjZF2-yJMc9IBIOxJhfzmWOB9z25rVq5dTjRo2n8_h1mGGrcJoX4eOPeEDNhqSuTtTXoEmYvHg9m0hE5B0agOcUocZqUL13G58KFBtsR9Nxq2LEoH42faZX3DVPv-IZAUqGcAkN76Np5QOUXyitojfYISUK0sDIWaPhqCQJLaaGkS1sOWjagxTqN2koNR9h_9BadmqONY1CDYGMx0qUhjr111OheDT1pll4g4jBjc7xQQ3eQpiTDl1cc-HDE3-r5FtI8kdXawl0FoyZAz6OZeBwEhsz5gghdqnqv6qaHwZgPl7ILiPMBx5VB2QmxrgYsMcjWEEVvhchv3KIBhRk-_QGXc8rO5dTrtBw9Ie0KIom6U28XAyfmLj9rL_d1_yw-j_ub0c4Fc7Nsc7a674RY8yK5S4PI3Gk4W76IGEsTvkHRXWN_jQ6LJPsm2Ig-GCH4OpZHb8BVIcrd7NRKsT8pWFo2n2kCPK1x96jqDrpmAwlTXtQDvUspNPb0SIWgAfNfrGZJhG9yLkxT4ofarbP8irV-poHOKkqaX-KXb9yzOzHrlIaAqX7FUMLoMIqM6-fCGOZLAnT5es8T3uHX7ueurwHarrM5ss-IPWQ36yVv0As0ErtJce0evXDVC6FE0XcvSolAwnPZAmnUvyN2gv9G4H5ojJo-TjkS23TFE6ZZC7wv2wP_JvG9oPsI9cwm_C3ad2TpBcsVW4RcwI5SHdufNXbeLf82SgzIs-dVoEv3cir7Runa4TALpbxGAcZu0cDPXwfi6tlocJ1jFFcQ0HSc4L-f8HY5v9KcXepdcn0bHMg7DKpIw6_Ny3JXJ4eIUPcl_ZDlv-Q5N2Ec5n2aUuk4gh3GmLvih3N-aKkrpUal8-69VSRn4Y__Rlcp-btcRn6MR__i1F49s4F8Yaoz7fZhdCBP9hWSt0MCipwKRK3gyz4D2OAwtRfnzxHapclt-RgeWeJ0klMrrzEXHnN30PJMeFH88IyhGCr1UpLaxDH9DucSE3tm2Rj8RLy6IMNkiCOuA72fw5vHXfHdEeJwNSMHNu3w5aw8dU1q03b6BET_Nd-UG3tR5UW-ASQ3yOKcgxSOW-TzEPxvMCUnl4m50kyQViwcOJkrn0uN4b2icPv1fHuej9kGWTCcgysxPuFPcBQ1lyXZHvz2WyFqauVibISIzbFEuuZUfObod_r73ahELeFzv60-QcKr0hLJsGEsXystSTy14nHaskS3ks6oapZYl2JdRQ4wmW2PqmjpbgXoZ3PlOX3zSCHJ6y9eK-zF1lX5kM4DdYsvXQsiF3je2ZeZJFU3ynwA08XQyMypYUeGPXcvjffDdISQFvPgJ2qqN6_gno9oP0y9NiBGR1dLcxF10oUiqROWHdI5s5Lw2vfBWsoAPQJQpYYtiyubyKh5yHHOc-0jJl9_UVo2je5imPZiWMNYkgko5gQp0ZlbDbOKIW9BURiSGp0C5upkcRpi7OsuyHogSdRR0pvOv-h0zz9pFSYtcVCNl4eNtJIAJePsbUAqKcVmYEsORVR9HKuc5FAEDS064PvLZf9yuRkkOcuLNz6c5U3gjMxIHMJeaIBNhbL0ufEp7xdS-P6sU8k2695C_EpQJWGnpYXJUjF9Cgk37RGGXVdCgHGvSyBwTnJfzbkEefAxI_wJN4NEBv0fBm87vQ2tsOrW8M0mHQ0ircZxPwN5RdkDIHSxl-AVKAWVFi1Ma4bcx1vLcqPCUWjDDSDf8zqxFm_8T3v_eCthKWSYOeGN0H3sD5Fw3iOoYO7XzXvS-XHkY1n1UA9MGk5C-fJaSQW-hZiAWDoHy6j6yOxCERqnbnaM9lpE8Y1MGKDGJ4755EHsmCyPzL8WmIHCljRJe_THSCbLC_LT9V805dCXrl8TcCaUJcyJSNADalI0ILgg-VyuIYGHcZNEzWByq7jIB8B1Nx8jw3xFBoZSz7uhGn1dmNZpruOVTor2zR4sGSpOlJqP4q0UW-yBC5CE_LUGz_KrSYRis6GWusjyza3l9wODkV3-nf8usMuZoqimrj3ADg_H8oBhHOR9xojx6bbI1q0gKQ48NerQmXodC0hKux1ISOFNVpLitolbdQjlm9Eie47w_UNpVxiLyU2Q8I2thaZcG0S0hvi9PxmYNpDfX0O6Mz78J6OqiSZeSzlKkvR3LkHtK9NMDGvUbjc3qcp4t88j8a15aw8EL1AxqSgGo8OCCkEmz4MFdzjzuNAdMoPehfVpQWTi-q7YXybbgR_Qxtbwq7p3EoH1L4QI8tQpBRcn4RspdMqFKu2rup1EdRwdRMcSTCaq2Q23cS8WYDQw1oMOeb1TNerV-7PczgcWxikBRbQJSizVVQJlshJIXwl5CvyBGmQdpHLiFYxsJCLU5o5Ad1ao4UK5gt87ySvDgStzXWj0bvX0kV8XDT27vc2cBqAmXcel_KEuludHW-DM2hImPvsT-NVljmvhCYcjL_idAdpfJ5Oj3-PocJDNQXbve5QAAAAAAAAAAAAAAAAcPFBkjKw --amount 5`

# Verify a coin’s inclusion proof by id (hex)
cargo run --release --bin unchained -- proof --coin-id <64-hex>
```

## Configuration (edit `config.toml`)

- `[net]`: P2P port, bootstrap peers, optional `public_ip` (for NAT)
- `[p2p]`: rate limits and ban windows for chatty/bad peers
- `[storage]`: database path
- `[epoch]`: epoch length, difficulty bounds, retarget tuning
- `[mining]`: Argon2id memory bounds, attempts, workers, offload
- `[metrics]`: Prometheus bind address

Notes:
- If `storage.path` is relative, the node stores data under `~/.unchained/unchained_data`
- The shipped `config.toml` is a decent starting point

## Wallet and security

- Dilithium3 wallet keys are encrypted at rest with XChaCha20‑Poly1305
- Keys come from your passphrase via Argon2id (large memory, slow to brute‑force)
- Non‑interactive mode requires `WALLET_PASSPHRASE`
- Legacy plaintext wallets (if found) are migrated to encrypted format

Env vars that matter:
- `WALLET_PASSPHRASE` — passphrase for non‑interactive runs
- `PROOF_SERVER_TOKEN` — require `x-auth-token` for the proof server
- `COIN_MIRRORING=0` — disable writing `<db>/coins/coin-*.bin`

## Stealth receiving (how to get paid privately)

1) Export your stealth address (a signed bundle that binds your normal address to your Kyber768 public key):

```bash
cargo run --release --bin unchained -- stealth-address
```

Share this base64‑url string with senders. They’ll encrypt a one‑time Dilithium key to your Kyber PK. Your wallet can decrypt it, nobody else can.

2) Senders use the CLI:

```bash
cargo run --release --bin unchained -- send --stealth <STEALTH_ADDR> --amount 1
```

The wallet will:
- Use a legacy V1 transfer once for any coin that has never moved (to establish an owner one‑time key)
- Use V2 spends thereafter (Merkle‑anchored, blinded nullifier)

## V2 spend (PQ and practical)

Fields:
- `coin_id` — 32 bytes
- `root` — epoch Merkle root
- `proof` — inclusion proof for `coin_id` leaf
- `to` — stealth output `{ one_time_pk, kyber_ct, enc_one_time_sk, enc_sk_nonce }`
- `commitment` — BLAKE3(to.canonical_bytes())
- `nullifier` — BLAKE3("nullifier_v2" || spend_sk || coin_id)
- `sig` — Dilithium3 over `auth_bytes`

Authorization bytes: `auth_bytes = root || nullifier || commitment || coin_id`

Node checks:
1) Coin exists and the epoch anchor matches `root`
2) Merkle proof verifies
3) Nullifier hasn’t been seen
4) Signature verifies under current owner’s one‑time Dilithium public key

## Network and protocol

- Transport: QUIC over UDP (libp2p)
- Gossip: gossipsub topics (anchors, coins, transfers, spends, proofs)
- TLS: rustls + aws‑lc‑rs; prefers PQ/hybrid TLS 1.3

Peer identity lives in `peer_identity.key`. Keep it if you want a stable Peer ID.

## Proof server (HTTPS)

Run a local HTTPS endpoint to fetch proofs by coin id:

```bash
cargo run --release --bin unchained -- proof-server --bind 127.0.0.1:9090
```

Optional auth: set `PROOF_SERVER_TOKEN` and send `x-auth-token` header.

Example request:

```bash
curl -s \
  -H "x-auth-token: $PROOF_SERVER_TOKEN" \
  https://127.0.0.1:9090/proof/<COIN_ID_HEX> | jq .
```

Response (example):

```json
{
  "ok": true,
  "response": {
    "coin": "…",
    "epoch": 123,
    "merkle_root": "…",
    "proof_len": 17
  }
}
```


Notables: `unchained_peer_count`, `unchained_epoch_height`, `unchained_selected_coins`, `unchained_coin_proofs_served_total`, `unchained_mining_*`.

## Data storage

- RocksDB column families: `epoch`, `coin`, `coin_candidate`, `anchor`, `transfer`, `spend`, `nullifier`, …
- Optional coin mirroring: `<db>/coins/coin-<id>.bin` (set `COIN_MIRRORING=0` to disable)
- Simple backups: `<db>/backups/<timestamp>/`

## Mining and epochs (how blocks happen)

- Time is chunked into epochs (`[epoch].seconds`)
- Miners produce coin candidates by meeting Argon2id difficulty
- Each epoch selects up to `[epoch].max_coins_per_epoch` (best PoW) and commits IDs into a Merkle root
- Difficulty and Argon2 memory adjust to aim for `[epoch].target_coins_per_epoch`

## Troubleshooting

- DB locked: don’t share `storage.path` across processes; only delete `LOCK` if the node is stopped
- No peers: add at least one good `[net].bootstrap` multiaddr; open the UDP port or set `public_ip`
- NAT: forward UDP `listen_port`; set `public_ip`
- Non‑interactive: export `WALLET_PASSPHRASE`
- Metrics port busy: it will try the next port; check logs for the new bind
- Too chatty: pass `--quiet-net`

## What makes it post‑quantum?

- Dilithium3 for signatures and addresses (no classical curves)
- Kyber768 for KEM (stealth receiving without leaking long‑term keys)
- BLAKE3 + Argon2id (fast, modern, and not obviously broken by near‑term quantum)

Net effect: you run a normal node and use normal commands, but the cryptography underneath is built for the long haul.

---
