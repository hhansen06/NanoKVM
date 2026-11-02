# LDAP- und TACACS+-Anmeldung (Fork `hhansen06/NanoKVM`)

Dieser Fork erweitert die NanoKVM-Firmware (Cube / Lite) um die Anmeldung mit Konten aus
**LDAP / Active Directory** und **TACACS+**. Außerdem bezieht die Online-Aktualisierung in der
Web-Oberfläche ihre Pakete aus den GitHub-Releases dieses Forks.

## So funktioniert es

1. **Lokale Konten werden immer zuerst geprüft.** Existiert ein lokales Konto mit dem
   eingegebenen Namen, entscheidet nur dessen Passwort – der Name wird nie an ein Verzeichnis
   geschickt. Der lokale Geräteeigentümer (`admin`) funktioniert dadurch auch dann, wenn kein
   Verzeichnis erreichbar ist (Break-Glass-Zugang).
2. Sonst werden die aktivierten Verzeichnisse in der eingestellten Reihenfolge gefragt
   (Standard: TACACS+, dann LDAP). Das erste, das die Anmeldung annimmt, gewinnt.
3. Bei der ersten Anmeldung wird das Konto auf dem Gerät angelegt (Quelle `ldap` bzw.
   `tacacs`, ohne lokales Passwort). **Rolle und Berechtigungen werden bei jeder Anmeldung
   neu aus dem Verzeichnis übernommen.**
4. Externe Anmeldungen gelten nur `sessionDuration` Sekunden (Standard 8 h). Wird jemand
   im Verzeichnis gesperrt oder aus der Gruppe entfernt, endet der Zugang spätestens dann.
5. In der Benutzerverwaltung lassen sich externe Konten **sperren** (die Sperre bleibt auch bei
   späteren erfolgreichen Verzeichnis-Anmeldungen bestehen) und **löschen**. Rolle,
   Berechtigungen und Passwort sind dort nicht änderbar.

Benutzernamen werden normalisiert: `FIRMA\Max`, `max@firma.local` und `Max` ergeben alle das
Gerätekonto `max`. Ergibt ein Verzeichnisname den Namen eines lokalen Kontos, wird die
Anmeldung abgelehnt.

Fehlgeschlagene Anmeldungen – auch „Verzeichnis nicht erreichbar“ – zählen für die
Brute-Force-Sperre.

## Konfiguration

Entweder in der Web-Oberfläche unter **Einstellungen → LDAP / TACACS+** (nur Administratoren,
mit „Anmeldung testen“) oder direkt in der Datei **`/etc/kvm/external-auth.yaml`**
(Rechte `0600`, enthält Bind-Passwort und Shared Secret). Nach einer manuellen Änderung der
Datei den Dienst neu starten: `/etc/init.d/S95nanokvm restart`.

Ist die Datei fehlerhaft, bleibt die Verzeichnis-Anmeldung aus und die Web-Oberfläche zeigt
den Fehler an; lokale Konten funktionieren weiter.

### Rollen und Berechtigungen

Rollen: `admin` (alles) und `user` (nur die angegebenen Berechtigungen).
Berechtigungen für `user`:

| ID | Bedeutung |
|---|---|
| `console.view` | Bildschirm ansehen |
| `console.control` | Tastatur & Maus |
| `power` | Ein/Aus/Reset, Wake-on-LAN |
| `medium.attach` | Medien einbinden |
| `library.read` / `library.write` | Medienbibliothek lesen / verwalten |
| `terminal` | Root-Shell & Skripte |
| `device` / `network` / `update` | Geräte-, Netzwerk-, Update-Einstellungen |
| `tailscale` | Tailscale |

Passen mehrere Regeln, gewinnt die stärkste Rolle, die Berechtigungen werden vereinigt. Passt
keine Regel und ist keine `defaultMapping` gesetzt, wird die Anmeldung abgelehnt.

### Beispiel: Active Directory

```yaml
order: [ldap]
sessionDuration: 28800
ldap:
  enabled: true
  urls: ["ldaps://dc1.firma.local:636", "ldaps://dc2.firma.local:636"]
  caFile: /etc/kvm/firma-ca.pem          # leer = System-CAs
  bindDN: "CN=svc-nanokvm,OU=Service,DC=firma,DC=local"
  bindPassword: "geheim"
  baseDN: "DC=firma,DC=local"
  userFilter: "(&(objectClass=user)(sAMAccountName=%s))"
  groupAttribute: memberOf
  timeout: 5
  groupMappings:
    - group: "CN=KVM-Admins,OU=Gruppen,DC=firma,DC=local"
      role: admin
    - group: "KVM-Operatoren"              # nur CN geht auch
      role: user
      permissions: [console.view, console.control, power, medium.attach]
```

Tipp: Verschachtelte AD-Gruppen auflösen mit
`userFilter: "(&(objectClass=user)(sAMAccountName=%s)(memberOf:1.2.840.113556.1.4.1941:=CN=KVM-Users,OU=Gruppen,DC=firma,DC=local))"`.

### Beispiel: OpenLDAP mit posixGroup

```yaml
ldap:
  enabled: true
  urls: ["ldap://ldap.firma.local:389"]
  startTLS: true
  bindDN: "cn=readonly,dc=firma,dc=local"
  bindPassword: "geheim"
  baseDN: "ou=people,dc=firma,dc=local"
  userFilter: "(uid=%s)"
  groupAttribute: ""
  groupSearchBaseDN: "ou=groups,dc=firma,dc=local"
  groupSearchFilter: "(&(objectClass=posixGroup)(memberUid=%u))"   # %d = User-DN
  groupMappings:
    - { group: kvm-admins, role: admin }
    - { group: kvm-users, role: user, permissions: [console.view, console.control] }
```

### Beispiel: TACACS+

```yaml
order: [tacacs, ldap]
tacacs:
  enabled: true
  servers: ["10.0.0.5:49", "10.0.0.6:49"]   # zweiter nur, wenn der erste nicht antwortet
  secret: "shared-secret"
  authenType: pap                            # pap | ascii
  service: nanokvm
  roleAttribute: nanokvm-role
  permissionsAttribute: nanokvm-perms
  privLvlMappings:                           # falls der Server keine nanokvm-role schickt
    - { minPrivLvl: 15, role: admin }
    - { minPrivLvl: 1, role: user, permissions: [console.view] }
  timeout: 5
```

Nach erfolgreicher Authentifizierung schickt das Gerät eine Autorisierungsanfrage mit
`service=nanokvm`. Ausgewertet werden (in dieser Reihenfolge): `nanokvm-role` (+
`nanokvm-perms`), dann `priv-lvl` über `privLvlMappings`, dann `defaultMapping`.

**tac_plus / tac_plus-ng** (Shrubbery-Syntax):

```
group = kvm-admins {
    service = nanokvm {
        nanokvm-role = admin
    }
}
group = kvm-operators {
    service = nanokvm {
        nanokvm-role = user
        nanokvm-perms = "console.view,console.control,power"
    }
}
user = max {
    login = des <hash>     # oder PAM/LDAP
    member = kvm-admins
}
```

**Cisco ISE:** Work Centers → Device Administration → Policy Elements → Results →
TACACS Profiles → neues Profil, *Common Task Type: None*, unter *Custom Attributes*
`nanokvm-role` = `admin` (Typ *Mandatory*) eintragen und das Profil in der
Device-Admin-Policy den NanoKVMs (als Network Devices mit dem Shared Secret anlegen) zuordnen.
Alternativ ein Shell-Profil mit `priv-lvl=15` und `privLvlMappings` verwenden.

## Firmware bauen und verteilen (GitHub Actions)

Einmalig im Fork:

1. **Actions aktivieren** (bei Forks standardmäßig aus): Repository → *Actions* → aktivieren.
2. Workflow **„Builder Image“** manuell starten. Er baut den RISC-V-Build-Container nach
   `ghcr.io/hhansen06/nanokvm-builder`. Damit auch Pull-Request-Builds ihn laden können, das
   Paket unter *Packages → nanokvm-builder → Package settings* auf **public** stellen.

Je Release:

1. Änderungen auf `main` bringen.
2. Workflow **„NanoKVM Create Tag“** mit einer neuen Version starten, z.B. `2.5.101`.
   Versionen müssen rein numerisch `MAJOR.MINOR.PATCH` sein (der On-Device-Updater lehnt
   Suffixe ab) und höher als die installierte Version. Schema: Upstream `2.5.1` → Fork `2.5.1xx`.
3. Workflow **„NanoKVM Release“** mit diesem Tag und `publish-stable` starten
   (oder erst `publish-prerelease` und nach dem Test `promote-stable`).

Das Release enthält `nanokvm_<version>.tar.gz`, `latest.json` und `sha256.txt`.

### Online-Update in der Web-Oberfläche

Die Firmware dieses Forks fragt
`https://github.com/hhansen06/NanoKVM/releases/latest/download/latest.json` ab. Sobald ein
neues **stabiles** Release veröffentlicht ist, erscheint es unter *Einstellungen → Update*
(Prereleases werden nicht angeboten). Prüfsummen (SHA-512 aus `latest.json`) werden auf dem
Gerät geprüft.

### Erstinstallation auf einem Gerät mit Original-Firmware

* Original-Firmware ab 2.5.1: *Einstellungen → Update → Eigener Update-Server* auf
  `https://github.com/hhansen06/NanoKVM/releases/latest/download` setzen und aktualisieren, **oder**
* *Einstellungen → Update → Offline-Update*: `nanokvm_<version>.tar.gz` aus dem Release hochladen.

Ältere Original-Firmware (ohne Mehrbenutzer) erst regulär auf 2.5.1 aktualisieren.

## Bekannte Grenzen

* Kein TACACS+-Accounting (nur Authentifizierung und Autorisierung).
* Kein RADIUS, kein SSO/OIDC.
* Die SSH-/Konsolen-Anmeldung am Gerät selbst (root) bleibt lokal; die Erweiterung betrifft
  die Web-Oberfläche.
* Wechselt ein Konto im Verzeichnis die Rolle, greift das bei der nächsten Anmeldung dieses
  Kontos (spätestens nach `sessionDuration`).
