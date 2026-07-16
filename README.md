# UDP Flow Limit Test — 10 Random Ports

Инструмент проверяет ограничение количества UDP-датаграмм на один persistent
UDP 5-tuple сразу на **10 разных случайных серверных портах**.

## Безопасная схема портов

Установщик **не открывает все UDP-порты**. Он открывает только:

- `62970/UDP` — фиксированный служебный порт обнаружения;
- 10 случайных свободных UDP-портов из диапазона `20000–60999`.

Windows-клиент не спрашивает порт. Он обращается к `62970/UDP`, получает список
10 тестовых портов и автоматически выполняет полный тест на каждом из них.

Случайный набор выбирается при каждой повторной установке серверной части.

## Установка на Linux

```bash
curl -fsSL   https://raw.githubusercontent.com/leric1977/udp-flow-limit-test/main/install-server.sh   -o /root/install-server.sh
chmod +x /root/install-server.sh
/root/install-server.sh
```

Запроса порта нет. Установщик выбирает 10 портов, настраивает UFW, firewalld,
nftables или iptables, запускает службу и выполняет локальную проверку.

Показать выбранные порты:

```bash
cat /etc/udp-flow-limit-test/ports.conf
```

## Запуск на Windows

```powershell
$u = 'https://raw.githubusercontent.com/leric1977/udp-flow-limit-test/main/windows/run-windows.ps1'
$p = Join-Path $env:TEMP 'run-udp-flow-test.ps1'
Invoke-WebRequest -UseBasicParsing $u -OutFile $p
powershell -NoProfile -ExecutionPolicy Bypass -File $p
```

Клиент спрашивает имя и адрес сервера, но не спрашивает порт. Он выполняет тест
на всех 10 случайных серверных портах и сохраняет TXT/JSON в `C:\2`.

Количество пакетов фиксировано: **100 в каждом подтесте**. Если uplink или любой
downlink-подтест не получает 100%, клиент автоматически повторяет только этот
подтест ещё максимум два раза. Каждая попытка использует новый token и новый
локальный исходный UDP-порт, то есть новый 5-tuple.

Фиксированный лимит подтверждается только при одинаковом результате во всех
трёх попытках uplink и обоих downlink-подтестов. Значения по умолчанию:
64 байта, интервал 50 мс, HELLO `1,3`.

## Внешний firewall

Скрипт меняет только firewall Linux. В Cloud Firewall или Security Group нужно
разрешить `62970/UDP` и 10 портов из `/etc/udp-flow-limit-test/ports.conf`.
