# Minimalist `whois` domain lookup

Single file `.php` script to fetch domain information from `whois` and `dig`. Supports exporting discovered records as [DNS .zone file](https://en.wikipedia.org/wiki/Zone_file). Run locally or on a web server that supports PHP and `shell_exec`. That can be accomplished by doing the following.
- `git clone https://github.com/austinginder/whois.git`
- `cd whois`
- `php -S localhost:8000`
- Then open http://localhost:8000


![](screenshot.webp)