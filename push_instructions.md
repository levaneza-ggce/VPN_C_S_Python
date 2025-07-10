# Instructions for Pushing Code to GitHub

## Prerequisites
- Git installed on your system
- GitHub account
- Repository created on GitHub (https://github.com/levaneza-ggce/VPN_C_S_Python.git)

## Authentication Methods

### 1. HTTPS with Personal Access Token (Recommended)
1. Generate a Personal Access Token (PAT) on GitHub:
   - Go to GitHub → Settings → Developer settings → Personal access tokens → Generate new token
   - Select the necessary scopes (at minimum, select "repo")
   - Copy the generated token

2. When pushing, use the token as your password:
   ```
   git push -u origin main
   ```
   - Username: your GitHub username
   - Password: your personal access token

### 2. SSH Authentication
1. Generate an SSH key if you don't have one:
   ```
   ssh-keygen -t ed25519 -C "your_email@example.com"
   ```

2. Add the SSH key to your GitHub account:
   - Copy your public key: `cat ~/.ssh/id_ed25519.pub`
   - Go to GitHub → Settings → SSH and GPG keys → New SSH key
   - Paste your key and save

3. Change the remote URL to use SSH:
   ```
   git remote set-url origin git@github.com:levaneza-ggce/VPN_C_S_Python.git
   ```

4. Push your code:
   ```
   git push -u origin main
   ```

## Troubleshooting

If you encounter issues:

1. Verify your remote URL:
   ```
   git remote -v
   ```

2. Check your Git configuration:
   ```
   git config --list
   ```

3. For authentication issues, try:
   ```
   git credential-osxkeychain erase
   ```
   (Replace osxkeychain with the appropriate helper for your OS)

4. If all else fails, you can manually upload your files to GitHub through the web interface.