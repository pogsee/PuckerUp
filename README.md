# PuckerUp
A web admin panel to administrate Puck servers, with HTML at the front, Go at the back.

## Complete server installation (Installs SteamCMD, Puck server, and PuckerUp)
Note, only tested with Ubuntu 24.04. Workarounds are needed for Debian 13 to install SteamCMD. 

Also, if you already have server configs under /srv/puckserver, please back these up, the script will overwrite them. I did this to get new hosters started with a usable config. You can always comment these lines if you want - the panel will handle existing configs.

-Grab the script with `wget https://raw.githubusercontent.com/pogsee/PuckerUp/main/PuckerUp.sh`

-Make it executable with `chmod +x PuckerUp.sh`

-Run the script with `./PuckerUp.sh`

The script will present you with a URL to access, and your passwords. Save the PuckerUp password as it will not be shown again.

## Manual installation
Not happening yet - a lot of work with hardcoded paths across all files right now. You are welcome to edit the go files and use build.sh, edit the script to fit your needs etc. In the future I may add an option to install PuckerUp only.

## Instructions/notes
Not much to it - login at the URL, set what you want to set, and save the changes. Restart the server for changes to take effect.

There is bruteforce protection built in, wrong password 5 times will result in an IP block for 10 minutes.

You can change the panel password by logging into the server and executing `/srv/PuckerUp/puckerup-passwd`. Note this will not log out existing sessions (cookies are 24 hours I think).

This is my first time vibe coding anything more than a shell script, so pls go easy :) Feature suggestions and bug reports are welcomed.

The Daily Scheduled Restart option creates a file under /srv/puckserver/schedules.json

## Credits
Gafurix for the cool game https://steamcommunity.com/app/2994020
VotePause and VoteForfeit mods by https://github.com/ViliamVadocz/
Crash Exploit Fix by https://github.com/ckhawks
