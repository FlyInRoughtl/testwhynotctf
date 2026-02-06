# Gargoyle CTF Cheatsheet (3.1.3r)

1) Запуск TUI  
`gargoyle start --tui`

2) Статус  
`gargoyle status`

3) Применить сеть (Linux)  
`gargoyle start --apply-network`

4) Mesh recv (приём файлов)  
`gargoyle mesh recv --listen :19999 --out ./downloads --psk secret --transport tls`

5) Mesh send (отправка файлов)  
`gargoyle mesh send ./file.txt file.txt --to 1.2.3.4:19999 --security --psk secret --transport tls`

6) Relay (публичная сеть)  
`gargoyle relay --listen :18080`

7) Hub (webhook/drop)  
`gargoyle hub start --listen 127.0.0.1:8080`

8) EmulateEL (GUI)  
`gargoyle emulate run firefox`

9) Tools pack  
`gargoyle install pack-ctf`

10) Doctor  
`gargoyle doctor`

11) Update  
`gargoyle update --url https://.../gargoyle --sha256 <sum> --sig <sig_b64> --pub <pub_b64>`

12) Wipe  
`gargoyle wipe --emergency`
