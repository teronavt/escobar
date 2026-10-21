# Escobar

Escobar — локальный перенаправляющий HTTP-прокси на Go, альтернатива `cntlm`. Он принимает запросы приложений без корпоративной авторизации и отправляет их через вышестоящий прокси, добавляя необходимые заголовки авторизации. Основной вариант — Kerberos/SPNEGO; для сетей без доступного KDC предусмотрен режим Basic.

Первоначально проект тестировался с McAfee Web Gateway. Escobar работает в Linux, macOS и Windows; поддержка других систем зависит от используемых библиотек.

Кроме прокси-сервера (по умолчанию `127.0.0.1:3128`), Escobar запускает небольшой HTTP-сервер (по умолчанию `127.0.0.1:3129`) с адресами:

- `GET /proxy.pac` — файл автоматической настройки прокси (PAC);
- `GET /ca.crt` — сертификат, предоставляемый программой. Перед добавлением сертификата в доверенные обязательно проверьте, что это доверенный корпоративный центр сертификации, а не сертификат отдельного веб-сайта.

> Для опубликованных сборок этого форка см. [GitHub Releases](https://github.com/teronavt/escobar/releases). Установка и настройка приведены ниже.

## Установка

### Ubuntu 24.04, 26.04 и 26.10

Релизный workflow публикует три DEB-пакета для архитектуры **amd64**:

```text
escobar_<VERSION>-1ubuntu24.04_amd64.deb
escobar_<VERSION>-1ubuntu26.04_amd64.deb
escobar_<VERSION>-1ubuntu26.10_amd64.deb
SHA256SUMS
```

Скачайте пакет, соответствующий версии Ubuntu, и проверьте контрольную сумму по `SHA256SUMS`, опубликованному в том же релизе:

```bash
sha256sum -c --ignore-missing SHA256SUMS
sudo apt install ./escobar_1.2.3-1ubuntu26.04_amd64.deb
escobar --version
```

В командах выше `1.2.3` — пример версии. Замените её и номер Ubuntu на значения выбранного релиза. Пакет устанавливает `/usr/bin/escobar` и шаблонный unit `escobar@.service`, но **не включает автозапуск**: сначала необходимо задать параметры корпоративного прокси и способ авторизации. Личные ключи и пароли в пакет не входят.

### Сборка из исходного кода

Требуется Go 1.19 или новее.

```bash
go build -o escobar ./cmd/escobar
./escobar --help
```

Тесты проекта используют monkey patching, поэтому для них необходимо отключать встраивание (inlining):

```bash
go test -gcflags=-l ./...
```

## Использование

В примерах ниже `proxy.example.corp:3128` — корпоративный прокси, `EXAMPLE.CORP` — realm Kerberos, `dc.example.corp` — контроллер домена. **Замените эти значения своими**. Никогда не публикуйте keytab или токены `Proxy-Authorization`.

### Быстрый запуск: Kerberos auto

В Linux режим `auto` использует существующий Kerberos credential cache текущего пользователя; в Windows — SSPI.

```bash
kinit user@EXAMPLE.CORP
klist

export KRB5CCNAME=FILE:/tmp/krb5cc_$(id -u)
escobar -d http://proxy.example.corp:3128/ -v
```

Если корпоративные настройки уже создают TGT, повторный `kinit` не требуется. Чтобы проверить местный прокси из другого терминала:

```bash
curl -v --proxy http://127.0.0.1:3128 \
  https://example.com/ -o /dev/null
```

**Не передавайте `--proxy-negotiate` и `--proxy-user` при обращении к Escobar:** их должен использовать сам Escobar при запросе к корпоративному прокси.

Можно сменить URL стартовой проверки (по умолчанию `https://www.google.com/`) на разрешённый в вашей сети HTTPS-ресурс:

```bash
escobar -d http://proxy.example.corp:3128/ \
  --proxy.ping-url=https://example.com/ -v
```

### Сначала проверьте Kerberos и Squid без Escobar

Для отделения проблем Escobar от проблем сети и аутентификации используйте `curl` напрямую к корпоративному прокси:

```bash
curl -v --proxy-negotiate --proxy-user : \
  --proxy http://proxy.example.corp:3128/ \
  https://example.com/ -o /dev/null
```

Успешная авторизация даст `HTTP/1.1 200 Connection established`. Наличие TGT (`krbtgt/EXAMPLE.CORP@EXAMPLE.CORP`) **не означает**, что билет `HTTP/proxy.example.corp@EXAMPLE.CORP` уже существует: при необходимости GSSAPI получает его автоматически.

```bash
klist -e
KRB5_TRACE=/dev/stderr kvno HTTP/proxy.example.corp@EXAMPLE.CORP
```

Если `kvno` с явно указанным realm успешен, а `curl` выдаёт `KDC не поддерживает тип шифрования`, сначала выясните, **какой realm curl выбирает на самом деле**:

```bash
KRB5_TRACE=/dev/stderr curl -v --proxy-negotiate --proxy-user : \
  --proxy http://proxy.example.corp:3128/ \
  https://example.com/ -o /dev/null
```

Ищите `server principal HTTP/proxy.example.corp@...`. При ошибочном выборе realm настройте в `/etc/krb5.conf` конкретное соответствие домена и realm:

```ini
[domain_realm]
    proxy.example.corp = EXAMPLE.CORP
    .example.corp = EXAMPLE.CORP
    example.corp = EXAMPLE.CORP
```

**Не задавайте слишком широкое соответствие**, если разные подразделения используют разные Kerberos realms. Изменения в `/etc/krb5.conf` проверяйте новым `KRB5_TRACE` и `kvno -S HTTP proxy.example.corp`.

### HTTPS: ошибка `malformed HTTP status code "html"`

Некоторые версии Escobar ошибочно обрабатывают `CONNECT` после ответа Squid:

```http
HTTP/1.1 407 Proxy Authentication Required
Proxy-Authenticate: Negotiate
Content-Type: text/html
Content-Length: 3075
Connection: close
```

В таком случае прочитанный HTML из тела 407 принимается за следующий HTTP-статус, а повторный `CONNECT` отправляется в соединение, закрываемое Squid. Это **не проблема TGT**. Корректная реализация должна отправлять `Proxy-Authorization` к явно указанному прокси заранее и/или полностью читать тело 407 для keep-alive; при `Connection: close` она должна открыть новое TCP-соединение. Если ошибка воспроизводится в используемой версии, проверяйте реализацию `CONNECT` и обновление/исправление программы, а не меняйте шифры Kerberos ради обхода проблемы.

### HTTPS-инспекция: неизвестный корпоративный CA

После успешного CONNECT `curl` может завершаться с `SSL certificate problem: unable to get local issuer certificate`. Причина нередко в том, что корпоративный прокси выпускает подменные сертификаты сайтов от собственного CA. **Не используйте `-k` в постоянной конфигурации.** Получите доверенный корневой CA у администратора предприятия или с управляемой корпоративной машины, проверьте отпечаток и цепочку, затем установите PEM-сертификат:

```bash
sudo install -m 0644 corp-root-ca.crt \
  /usr/local/share/ca-certificates/corp-root-ca.crt
sudo update-ca-certificates
```

Проверка без `-k`:

```bash
curl -v --proxy-negotiate --proxy-user : \
  --proxy http://proxy.example.corp:3128/ \
  https://example.com/ -o /dev/null
```

Сертификат отдельного сайта и промежуточный сертификат прокси — не обязательно корневой CA. Не добавляйте сертификат неизвестного происхождения в системное хранилище доверия.

### Режим manual: keytab вместо сессионного TGT

Режим `manual` читает keytab и самостоятельно получает Kerberos-билеты. Он подходит для запуска при загрузке ОС без интерактивного `kinit`.

```bash
escobar -d http://proxy.example.corp:3128/ \
  -m manual \
  -u user \
  -k /home/user/.config/escobar/user.keytab \
  --proxy.kerberos.realm EXAMPLE.CORP \
  --proxy.kerberos.kdc dc.example.corp:88 \
  -v
```

Параметр `-u` содержит имя **без** `@REALM`, потому что realm указывается отдельно. Пользователь Linux, запускающий Escobar, и пользователь AD не обязаны совпадать. На личной рабочей станции допустимо запускать службу от своей учётной записи Linux. Отдельный системный пользователь целесообразен прежде всего для выделенного сервиса/учётной записи AD.

#### Создание keytab

Для Ubuntu с MIT Kerberos:

```bash
sudo apt install krb5-user
install -d -m 0700 ~/.config/escobar
umask 077
ktutil
```

Команды внутри `ktutil` (замените realm, principal и **текущий** KVNO):

```text
add_entry -password -p user@EXAMPLE.CORP -k <KVNO> -e aes256-cts-hmac-sha1-96 -f
write_kt /home/user/.config/escobar/user.keytab
quit
```

`-f` запрашивает у KDC сведения о соли ключа (важно для некоторых учётных записей AD с AES). Пароль вводится интерактивно. `touch` не создаёт keytab: файл должен иметь корректный двоичный формат. Проверьте содержимое:

```bash
chmod 600 ~/.config/escobar/user.keytab
klist -kte ~/.config/escobar/user.keytab
```

**Текущий KVNO нельзя всегда вычислить по формуле «старый + 1».** Обычно он увеличивается после смены пароля AD, но надёжнее читать атрибут `msDS-KeyVersionNumber` на контроллере домена:

```bash
sudo apt install ldap-utils
kinit user@EXAMPLE.CORP
ldapsearch -Y GSSAPI -H ldap://dc.example.corp \
  -b 'DC=example,DC=corp' '(sAMAccountName=user)' msDS-KeyVersionNumber
```

Используйте значение из вывода LDAP для `-k <KVNO>`. При необходимости используйте `ldaps://`, если это предусмотрено политикой домена.

Проверьте новый keytab независимо от Escobar, не перезаписывая основной ccache:

```bash
KRB5CCNAME=FILE:/tmp/escobar-kt-test \
  kinit -k -t ~/.config/escobar/user.keytab user@EXAMPLE.CORP
KRB5CCNAME=FILE:/tmp/escobar-kt-test \
  kvno HTTP/proxy.example.corp@EXAMPLE.CORP
KRB5CCNAME=FILE:/tmp/escobar-kt-test kdestroy
```

KVNO **пользователя**, помещаемый в keytab, и KVNO **прокси-сервиса**, выводимый последней командой `kvno HTTP/...`, — разные значения.

После смены пароля AD создайте новый keytab с новым паролем и актуальным KVNO, проверьте через `kinit -k`, затем атомарно замените старый файл и перезапустите Escobar. Для проверки старого keytab сообщения gokrb5 вида `matching key not found in keytab ... kvno: N etype: 18` указывают, какой KVNO AES256-ключа требуется, но предпочтительнее использовать LDAP.

#### Ошибки keytab

| Сообщение | Что проверить |
| --- | --- |
| `Unsupported key table format version number` | Файл пустой/текстовый; создайте его через `ktutil write_kt` |
| `matching key not found in keytab ... kvno: N etype: 18` | Неверный KVNO или тип ключа. `etype 18` — AES256 |
| `Preauthentication failed` или ошибка дешифрования | Пароль, Kerberos salt, текущий KVNO, актуальность учётной записи |
| `Permission denied` | Права на каталог `0700`, keytab `0600`, владелец — пользователь Escobar |
| `open /tmp/krb5cc_0: no such file` | Системная служба запущена от root в режиме `auto`, хотя билеты в ccache пользователя с другим UID; смените `User=` или используйте `manual` |

### Запуск через systemd

DEB-пакет содержит **шаблон** `escobar@.service`. Экземпляр `%i` означает Linux-пользователя, от которого он запускается. Система не включает службу автоматически и не копирует ваши Kerberos-ключи.

Например, для пользователя `localadmin` создайте `/etc/default/escobar-localadmin` (в этом файле только настройки/пути, не пароль):

```ini
ESCOBAR_PROXY_DOWNSTREAM_PROXY_URL=http://proxy.example.corp:3128/
ESCOBAR_PROXY_MODE=manual
ESCOBAR_PROXY_DOWNSTREAM_PROXY_AUTH_USER=user
ESCOBAR_PROXY_DOWNSTREAM_PROXY_AUTH_KEYTAB=/home/localadmin/.config/escobar/user.keytab
ESCOBAR_PROXY_KERBEROS_REALM=EXAMPLE.CORP
ESCOBAR_PROXY_KERBEROS_KDC=dc.example.corp:88
ESCOBAR_PROXY_PING_URL=https://example.com/
```

```bash
sudo install -m 0600 /dev/null /etc/default/escobar-localadmin
sudoedit /etc/default/escobar-localadmin
sudo systemctl daemon-reload
sudo systemctl enable --now escobar@localadmin.service
sudo systemctl status escobar@localadmin.service
journalctl -u escobar@localadmin.service -n 50 --no-pager
```

Шаблон ссылается на `/usr/bin/escobar`; `User=localadmin` задаётся экземпляром службы. Файл keytab должен читаться `localadmin`. Если запустить `auto`-режим от root, по умолчанию будет использоваться `/tmp/krb5cc_0`, а не личный ccache. При запуске ручного режима с keytab личный ccache вообще не нужен.

Проверка:

```bash
curl -v --proxy http://127.0.0.1:3128 \
  https://example.com/ -o /dev/null
```

Не включайте одновременно установленную ранее службу `escobar.service` и новую `escobar@localadmin.service`, если обе пытаются занять `127.0.0.1:3128`.

### Встроенная установка в качестве службы

В программе также предусмотрена команда:

```bash
sudo escobar -d http://proxy.example.corp:3128/ --install
```

Она создаёт системную службу с параметрами Escobar. Расположение файла `settings.json` зависит от ОС и настроек XDG:

| ОС | Расположение по умолчанию |
| --- | --- |
| Windows | `%PROGRAMDATA%\Escobar\Escobar\settings.json` |
| Linux/BSD | `${XDG_CONFIG_DIRS}/etc/xdg/Escobar/Escobar/settings.json` (зависит от XDG) |
| macOS | `/Library/Application Support/Escobar/Escobar/settings.json` |

Не используйте одновременно встроенный инсталлятор службы и `escobar@.service` из DEB для одного порта. При использовании DEB рекомендуется описанный выше шаблон `systemd`.

Пример структуры настроек (время в JSON задаётся в наносекундах):

```json
{
  "proxy": {
    "addr": "localhost:3128",
    "downstreamProxyURL": "http://proxy.example.corp:3128/",
    "downstreamProxyDialRetries": 0,
    "downstreamProxyAuth": { "user": "", "password": "", "keytab": "" },
    "kerberos": { "realm": "", "kdc": "" },
    "timeouts": {
      "server": { "readTimeout": 0, "readHeaderTimeout": 30000000000, "writeTimeout": 0, "idleTimeout": 60000000000 },
      "client": { "readTimeout": 0, "writeTimeout": 0, "keepAlivePeriod": 60000000000 },
      "downstreamProxy": { "dialTimeout": 10000000000, "readTimeout": 0, "writeTimeout": 0, "keepAlivePeriod": 60000000000 }
    },
    "pingURL": "https://www.google.com/",
    "mode": "auto"
  },
  "static": { "addr": "localhost:3129" },
  "useSystemLogger": true,
  "verbose": [true]
}
```

## Основные параметры командной строки

Для полной актуальной справки запускайте `escobar --help`. Короткие опции могут записываться как `-d`, полные — как `--proxy.downstream-proxy-url`.

| Параметр | Назначение |
| --- | --- |
| `-l`, `--syslog` | Системный журнал |
| `--install`, `--uninstall` | Установка/удаление встроенной службы |
| `-v`, `--verbose` | Подробные сообщения |
| `-V`, `--version` | Версия |
| `-a`, `--proxy.addr` | Локальный адрес (обычно `localhost:3128`) |
| `-d`, `--proxy.downstream-proxy-url` | URL вышестоящего прокси |
| `-r`, `--proxy.downstream-proxy-dial-retries` | Повторные подключения к вышестоящему прокси |
| `--proxy.ping-url` | URL проверки доступности и авторизации |
| `-m`, `--proxy.mode` | Режим `auto`, `manual` или `basic` |
| `-u`, `--proxy.downstream-proxy-auth.user` | Пользователь корпоративного прокси |
| `-p`, `--proxy.downstream-proxy-auth.password` | Пароль для поддерживаемого режима (не передавайте в открытом виде без необходимости) |
| `-k`, `--proxy.downstream-proxy-auth.keytab` | Путь к keytab |
| `--proxy.kerberos.realm`, `--proxy.kerberos.kdc` | Realm и KDC |
| `--static.addr` | Адрес PAC/CA HTTP-сервера (обычно `localhost:3129`) |
| `--proxy.timeouts.server.read`, `.read-header`, `.write`, `.idle` | Тайм-ауты HTTP-сервера |
| `--proxy.timeouts.client.read`, `.write`, `.keepalive-period` | Тайм-ауты клиента |
| `--proxy.timeouts.downstream.dial`, `.read`, `.write`, `.keepalive-period` | Тайм-ауты вышестоящего прокси |

Для параметров доступны переменные окружения вида `ESCOBAR_PROXY_DOWNSTREAM_PROXY_URL`, `ESCOBAR_PROXY_MODE`, `ESCOBAR_PROXY_KERBEROS_REALM`. Полный список отображается через `--help`.

## Статус и лицензия

Проект поставляется «как есть», без гарантии работы в любой сетевой конфигурации.
