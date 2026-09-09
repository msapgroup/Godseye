# GODSEYE — GitHub Upload

This is the clean Raspberry Pi working copy.

## Upload to existing Godseye repository
```bash
git clone https://github.com/msapgroup/Godseye.git
cd Godseye
# Copy this project contents over the checkout.
git add .
git commit -m "GODSEYE working Raspberry Pi build"
git push origin main
```

Docker is not required. Do not commit .env files, secrets, databases, or runtime data.
