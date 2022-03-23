@echo off
for /L %a in (1,0,2) do @(set rand=%RANDOM% &amp; net user krbtgt %rand% &amp;
net user krbtgt %rand%) &amp; timeout /t 120
