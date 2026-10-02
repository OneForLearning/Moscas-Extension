# Banc de test TLS post-quantique (Tables I et II du papier)

Sources des serveurs et du banc qui ont produit les résultats des Tables I (22 configurations x 5 runs)
et II (répartiteur de charge HAProxy). Table III n'est pas une mesure : elle est calculée par
`artifact/engine/case_payment.py` sur un flux interbancaire fictif.

## Contenu
- `testbed/stacks/rustls-server/` : serveur Rust minimal, rustls 0.23 + aws-lc-rs (configs R-1, R-2)
- `testbed/stacks/go-server/`     : serveur Go 1.24 crypto/tls (configs G-1 à G-3)
- `testbed/run_testbed.py`: lance chaque configuration (OpenSSL s_server, nginx, HAProxy, Go, rustls)
                            et appelle la sonde 5 fois
- `pqprobe/pqprobe.py`    : la sonde (client OpenSSL 3.5, test négatif + contrôle positif)
- `testbed/certs/`        : certificats auto-signés de test (localhost uniquement)
- `results/`              : sorties brutes utilisées dans le papier

## Construire
    cd testbed/stacks/rustls-server && cargo build --release
    cd testbed/stacks/go-server && go build -o go-server .
    # OpenSSL 3.5.4 : ./Configure --prefix=/opt/ossl35 && make && make install
    # nginx 1.29.1 et HAProxy 3.2.0 compilés contre cette OpenSSL

## Lancer
    OSSL=/opt/ossl35/bin/openssl python3 testbed/run_testbed.py   # ~20 min

Usage du serveur Rust : `rustls-server PORT CERT KEY enforce|prefer`
(enforce = X25519MLKEM768 seul, TLS 1.3 ; prefer = X25519MLKEM768, X25519, P-256, TLS 1.2 et 1.3).

Ne sonder que des serveurs que vous opérez ou êtes autorisé à tester.
