# mailcheck-vps

Diagnóstico de entregabilidad de correo **desde adentro del servidor**, en
modo solo lectura: lee `main.cf` de Postfix y `opendkim.conf`, deriva la clave
pública DKIM de la clave privada local, la compara con lo publicado en DNS, y
evalúa SPF, DMARC, PTR/rDNS, HELO, IPv6, TLS, MX, 3 listas DNSBL y la salida al
puerto 25. Devuelve las causas raíz **ordenadas** (qué arreglar primero) con el
comando o el registro DNS exacto para corregirlas.

> Estado: **MVP de un día**. Es el núcleo de la CLI más un laboratorio que
> prueba su valor. El producto completo (ver "Fuera de alcance") se estima en
> unas 3 semanas de una persona.

## Uso

```sh
pip install "cryptography>=41"
python -m mailcheck diagnose \
  --main-cf /etc/postfix/main.cf \
  --opendkim-conf /etc/opendkim.conf \
  --ipv4 192.0.2.10 --ipv6 2001:db8::10 \
  --probe mx.example.net:25          # opcional: prueba la salida al 25
# --zone-file zona.json  -> DNS desde un archivo (sin red)
# --dns-server <ip>      -> DNS real vía `dig` (sin consultas reales en los tests)
# --json                 -> salida estructurada

python -m mailcheck dkim-pub --key /etc/opendkim/keys/mail.private   # valor p= a publicar
```

Códigos de salida: `0` todo OK, `1` hay fallas, `3` incompleto (algo no se
pudo chequear; nunca se informa OK por algo que no se miró), `2` error de uso.

Chequeos y causa raíz que reporta, en el orden en que se recomienda arreglar:

| Causa | Qué mira |
|---|---|
| `port25_blocked` | conexión TCP saliente a `--probe` |
| `dnsbl_listed` | zen.spamhaus.org, bl.spamcop.net, b.barracudacentral.org (consulta A sobre la IP invertida) |
| `ptr_missing`, `ptr_mismatch` | PTR de la IPv4, que coincida con `myhostname` y confirme hacia adelante (A) |
| `helo_mismatch` | `smtp_helo_name` (por defecto `$myhostname`) contra el PTR |
| `spf_missing`, `spf_permerror`, `spf_ip_not_authorized` | evaluación SPF de la IPv4 del servidor |
| `dkim_config_missing`, `dkim_record_missing`, `dkim_key_mismatch`, `dkim_unaligned` | Selector/Domain/KeyFile de OpenDKIM contra `selector._domainkey.dominio` |
| `dmarc_missing`, `dmarc_invalid` | `_dmarc.dominio` con `p=` válido |
| `ipv6_no_ptr`, `ipv6_spf` | si `inet_protocols` permite IPv6: PTR y SPF de la IPv6 |
| `tls_missing` | `smtpd_tls_cert_file`/`key_file` existen y `smtp_tls_security_level` habilita STARTTLS |
| `mx_missing`, `spf_too_permissive` | MX del dominio; SPF con `+all` |

## Qué está probado

Medido en esta máquina (Linux x86_64, Python 3.13) el 2026-10-27:

```sh
python -m lab.measure
# root cause correct: 12/12; false OK: 0; healthy control OK: True; criterion met: True
```

- **Laboratorio**: 12 configuraciones rotas a propósito, una falla por caso
  (`lab/cases.py`), más un caso sano de control. Criterio fijado antes de
  correr: causa raíz correcta en >= 11/12 y 0 casos rotos marcados OK.
  **Resultado: 12/12, 0 falsos OK, control sano = OK.** Repetido 3 veces
  seguidas con claves DKIM nuevas en cada corrida: mismo resultado.
- **Tests**: `python -m tests.run` corre 33 tests (parser de `main.cf` y
  `opendkim.conf`, evaluador SPF con include/redirect/límite de 10 lookups,
  DKIM coincide/no coincide/revocada/ilegible, alineación, DMARC, orden de
  causas, CLI, y los argumentos que se le pasan a `dig`, incluidos nombres
  que empiezan con `-` o `+`). Un test salteado cuenta como falla.
- Todo es offline: el DNS del laboratorio es un archivo JSON, las claves se
  generan en un directorio temporal en cada corrida (no hay claves en el repo)
  y solo se usan nombres y direcciones de documentación (`example.com/.net`,
  `192.0.2.0/24`, `2001:db8::/32`). Un test verifica esto sobre `lab/cases.py`.

## Qué NO está probado (límites honestos)

- **El laboratorio lo escribió el mismo autor que la herramienta.** Cada caso
  tiene una sola falla y la herramienta se diseñó conociendo esas 12 fallas;
  12/12 muestra que los chequeos hacen lo que dicen, no que cubran los
  problemas de un servidor real. Con varias fallas a la vez, el orden de
  causas es una heurística (`CAUSE_ORDER` en `mailcheck/checks.py`).
- La idea original pedía un laboratorio con Postfix + OpenDKIM reales en
  Docker; **hoy no se levantó ningún Postfix ni OpenDKIM**: se parsean sus
  archivos de configuración y el DNS es simulado.
- **No se probó contra un servidor real** ni se midió el resultado de
  mail-tester después de aplicar las correcciones (la meta de >= 9/10 queda
  pendiente).
- El backend de DNS real (`--dns-server`, vía `dig`) **no hace consultas reales
  en ningún test**: los tests verifican con `subprocess` simulado que el nombre
  va siempre detrás de `-q` (así un nombre que empieza con `-` o `+` no se lee
  como opción), y un job de CI comprueba con el `dig` real que lo toma como
  nombre. La resolución y el parseo de respuestas reales no están probados.
- El chequeo de TLS solo verifica que los archivos existan y el nivel de
  seguridad configurado; no valida el certificado ni hace STARTTLS.
- SPF: no implementa macros, `exists:` ni `ptr:` (devuelven `permerror`), ni el
  límite de "void lookups".
- La IP pública se pasa por argumento; no se detecta sola.

## Fuera de alcance

Exchange / Microsoft 365 / Google Workspace; warming de IP; email marketing;
rspamd (hoy solo OpenDKIM); modificar el servidor (la herramienta es solo
lectura y únicamente imprime los comandos de corrección).

## Fuentes que se leyeron

- RFC 7208 (SPF), secciones 4.6.4 (límite de 10 lookups), 5.2 (tabla de
  resultados de `include`) y 6.1 (`redirect`):
  https://www.rfc-editor.org/rfc/rfc7208
- Demanda: pedido abierto en Freelancer "Email Deliverability Specialist for
  VPS/Mail-Server Optimization", USD 150-300 precio fijo, 27 ofertas (leído
  por la API pública el 2026-10-27):
  https://www.freelancer.com/projects/dns/Email-Deliverability-Specialist-for-VPS

## Contribuir, reportar errores y seguridad

*English version: [README.en.md](README.en.md).*

- Errores y pedidos de mejora: <https://github.com/federiconbaez/cortex9-mailcheck-vps/issues>
- Cómo contribuir (proceso de PR, requisitos y tests): [CONTRIBUTING.md](CONTRIBUTING.md)
- Vulnerabilidades, por canal privado: [SECURITY.md](SECURITY.md)
- Cambios por versión: [CHANGELOG.md](CHANGELOG.md)

## Licencia

Apache-2.0. Ver `LICENSE`.
