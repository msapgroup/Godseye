# Create the new GODSEYE GitHub repository

Recommended repository name: `Godseye`.

```bash
git init
git add .
git commit -m "Initial GODSEYE network intelligence build"
git branch -M main
git remote add origin https://github.com/YOUR-GITHUB-ACCOUNT/Godseye.git
git push -u origin main
```

Do not commit `.env`, databases, secrets, runtime logs, or generated caches.

## Raspberry Pi

```bash
cd Godseye
sudo bash install.sh
```

Then open `http://PI-IP:8080`.
