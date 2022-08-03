@echo off
set MAINFOLD=%1
if not defined MAINFOLD goto :eof
if not exist %~dp0\%MAINFOLD% goto :eof

::initialize
cd /d %~dp0\%MAINFOLD%\attach
echo ### -*- -*- -*- -*- -*- -*- Start processing in %MAINFOLD% -*- -*- -*- -*- -*- -*-
chcp 65001
del /f /q *.txt>nul 2>nul
del /f /q *.exe>nul 2>nul
del /f /q *.yaml>nul 2>nul
::bypass detection
set wgetFix=-nv --no-config -t 3 --no-netrc -T 30 --connect-timeout=10 --read-timeout=10 -w 1 -4 --no-iri --no-cache -U "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1 SearchCraft/3.9.0 (Baidu; P2 16.0)" --no-cookies --https-only --no-hsts --local-encoding=UTF-8 --remote-encoding=UTF-8 --restrict-file-names=nocontrol
set curlFix=-L -q --connect-timeout 10 -k -4 -m 30 -e "https://google.com/" -s -S -A "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1 SearchCraft/3.9.0 (Baidu; P2 16.0)"

::enable proxy in China local machine (not needed)
set isproxy=0
set httproxy=172.16.0.2:8899

if %isproxy%==1 set curlproxy= -x %httproxy%
if %isproxy%==1 set http_proxy=%httproxy%
if %isproxy%==1 set https_proxy=%httproxy%

::get binaries
curl %curlFix%%curlproxy% --url https://raw.githubusercontent.com/DoingDog/DoingDog/main/wget.exe -o wget.exe
curl %curlFix%%curlproxy% --url https://raw.githubusercontent.com/DoingDog/DoingDog/main/busybox.exe -o busybox.exe
if not exist .\wget.exe (
del /f /q *.exe>nul 2>nul
goto :eof
)
if not exist .\busybox.exe (
del /f /q *.exe>nul 2>nul
goto :eof
)

::clear old
del /f /q ..\*.txt>nul 2>nul
del /f /q ..\*.yaml>nul 2>nul

::down and process All rule links, remove unsupported rules
echo ###Start processing ordinary rules
for /f "eol=# tokens=1,2 delims= " %%i in (rule-list.ini) do (
wget %wgetFix% -O 2.txt %%i
busybox sed -i -E "/^$/d" 2.txt
busybox sed -i -E "/\#./d" 2.txt
busybox sed -i -E "/^[^iI].*\:/d" 2.txt
busybox sed -i -E "/^[^iI].*\//d" 2.txt
busybox sed -i -E "/^ /d" 2.txt
busybox sed -i -E "s/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ +//g" 2.txt
busybox sed -i -E "s/ //g" 2.txt
busybox sed -i -E "s/^-//g" 2.txt
busybox sed -i -E "s/,no-resolve$//g" 2.txt
busybox sed -i -E "/^.*REGEX.*$/d" 2.txt
busybox sed -i -E "/^.*AND.*$/d" 2.txt
busybox sed -i -E "/^.*NOT.*$/d" 2.txt
findstr .*,.*,.* 2.txt>nul && busybox sed -i -E "s/,[^,]+$//g" 2.txt && echo %%i AS BACK
findstr /b /c:"." /c:"b" /c:"c" /c:"e" /c:"f" /c:"j" /c:"k" /c:"l" /c:"o" /c:"q" /c:"t" /c:"v" 2.txt>nul && busybox sed -i -E "s/^/DOMAIN,/g" 2.txt && busybox sed -i -E "s/^DOMAIN,\./DOMAIN-SUFFIX,/g" 2.txt && echo %%i AS DOMAINSET
busybox sed -i -E "s/^host/domain/g" 2.txt
busybox sed -i -E "s/^HOST/DOMAIN/g" 2.txt
busybox sed -i -E "s/^ip6-cidr/ip-cidr6/g" 2.txt
busybox sed -i -E "s/^IP6-CIDR/IP-CIDR6/g" 2.txt
busybox sed -i -E "s/^domain-keyword/DOMAIN-KEYWORD/g" 2.txt
busybox sed -i -E "s/^domain-suffix/DOMAIN-SUFFIX/g" 2.txt
busybox sed -i -E "s/^domain/DOMAIN/g" 2.txt
busybox sed -i -E "s/^user-agent/USER-AGENT/g" 2.txt
busybox sed -i -E "s/^ip-cidr/IP-CIDR/g" 2.txt
busybox sed -i -E "/^D[^K]+,.*\.[0-9]+$/d" 2.txt
busybox sed -i -E "/^D.*,.*[A-Z]/d" 2.txt
echo.>>.\2.txt
type .\2.txt >>fas.txt
echo Downloaded
del /f /q 2.txt
)

::add manual rules
if exist add.ini type add.ini >>fas.txt

::first deduplicate same lines
echo ###Start deduplicate same lines
set LC_ALL='C'
busybox sort -u -i -o fin.txt fas.txt
set LC_ALL=

::deduplicate same DOMAIN-SUFFIX using uniq
echo ###Start deduplicate same DOMAIN and DOMAIN-SUFFIX rule lines
busybox sed -i -E "/^$/d" fin.txt
busybox sed -i -E "/^ +$/d" fin.txt
busybox sed -n "/DOMAIN,/p" fin.txt>>fin-do.txt
busybox sed -n "/DOMAIN-SUFFIX,/p" fin.txt>>fin-ds.txt
busybox sed -i "/DOMAIN,/d" fin.txt
busybox sed -i "/DOMAIN-SUFFIX,/d" fin.txt
type fin-*.txt>>fn.txt
busybox sed -i -E "s/^[^,]+,//g" fn.txt
busybox sed -i -E "s/^[^,]+,//g" fin-do.txt
set LC_ALL='C'
busybox sort -i -o fbn.txt fn.txt
set LC_ALL=
busybox uniq -d fbn.txt>>fnn.txt
type fin-do.txt>>fnn.txt
set LC_ALL='C'
busybox sort -i -o frn.txt fnn.txt
set LC_ALL=
busybox uniq -u frn.txt>>fn2.txt
busybox sed -i -E "s/^/DOMAIN,/g" fn2.txt
type fn2.txt>>fin.txt
type fin-ds.txt>>fin.txt
set LC_ALL='C'
busybox sort -u -i -o xn.txt fin.txt
set LC_ALL=
busybox sed -n "/IP-CIDR/p" xn.txt>>fpip.txt
busybox sed -i "/IP-CIDR/d" xn.txt
busybox sed -i -E "s/$/,no-resolve/g" fpip.txt
type fpip.txt>>xn.txt
set LC_ALL='C'
busybox sort -u -i -o bn.txt xn.txt
set LC_ALL=

::remove too short
echo ###Start removing
busybox sed -i -E "/^$/d" bn.txt
busybox sed -i -E "/^.$/d" bn.txt
busybox sed -i -E "/^..$/d" bn.txt
busybox sed -i -E "/^...$/d" bn.txt
busybox sed -i -E "/^....$/d" bn.txt
busybox sed -i -E "/^.....$/d" bn.txt

if not exist del.ini goto :noexistdel
for /f "tokens=* delims=j" %%i in (del.ini) do (
echo Removing custom "%%i" ...
busybox sed -i -E "/%%i/d" bn.txt
)
:noexistdel

::count
echo ###Counting
for /f "tokens=2 delims=:" %%a in ('find /c /v "" bn.txt')do set/a bnrnum=%%a
echo # Main total line %bnrnum%>>bnr.txt
echo # Last updated %date% %time%>>bnr.txt
type bnr.txt
echo # -*- -*- -*- -*- -*- -*- -*- -*- -*- -*- -*- -*- -*- -*- -*- -*- -*- -*->>bnr.txt
type bn.txt>>bnr.txt
copy /y bnr.txt ..\fin.txt

::generate Quantumult type rules
echo ###Start generate Quantumult type rules
copy /y bn.txt cn.txt
busybox sed -i -E "s/$/,LIST/g" cn.txt
busybox sed -i -E "s/,no-resolve,LIST/,LIST,no-resolve/g" cn.txt
busybox sed -i -E "s/^DOMAIN/HOST/g" cn.txt
busybox sed -i -E "s/^IP-CIDR6/IP6-CIDR/g" cn.txt
busybox sed -i "/PROCESS-NAME/d" cn.txt
busybox sed -i "/DST-PORT/d" cn.txt
busybox sed -i "/SRC-PORT/d" cn.txt
busybox sed -i "/SRC-IP-CIDR/d" cn.txt
::Quantumult type rules
for /f "tokens=2 delims=:" %%a in ('find /c /v "" cn.txt')do set/a cnrnum=%%a
echo # Quantumult total line %cnrnum%>>cnr.txt
echo # Last updated %date% %time%>>cnr.txt
type cnr.txt
echo # -*- -*- -*- -*- -*- -*- -*- -*- -*- -*- -*- -*- -*- -*- -*- -*- -*- -*->>cnr.txt
type cn.txt>>cnr.txt
copy /y cnr.txt ..\fin-qx.txt

::generate Clash yaml type rules
echo ###Start generate Clash yaml type rules
copy /y bn.txt dn.txt
busybox sed -i -E "s/^/  - /g" dn.txt
::Clash yaml type rules
for /f "tokens=2 delims=:" %%a in ('find /c /v "" dn.txt')do set/a dnrnum=%%a
echo # Clash total line %dnrnum%>>dnr.txt
echo # Last updated %date% %time%>>dnr.txt
type dnr.txt
echo # -*- -*- -*- -*- -*- -*- -*- -*- -*- -*- -*- -*- -*- -*- -*- -*- -*- -*->>dnr.txt
echo payload:>>dnr.txt
type dn.txt>>dnr.txt
copy /y dnr.txt ..\fin.yaml

::clean
if %bnrnum% gtr 20 echo ### -*- -*- -*- -*- -*- -*- %MAINFOLD% File completely processed -*- -*- -*- -*- -*- -*-
del /f /q *.txt>nul 2>nul
del /f /q *.exe>nul 2>nul
del /f /q *.yaml>nul 2>nul
echo ###Cleaned
cd /d %~dp0
