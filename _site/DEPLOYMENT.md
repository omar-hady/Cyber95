# Deployment Guide

## Alternative Setup Methods

If you encounter permission issues with `bundle install`, here are alternative ways to run the Jekyll blog:

### Method 1: Using Docker (Recommended)

1. **Create a Dockerfile**:
   ```dockerfile
   FROM jekyll/jekyll:4.3.0
   COPY . /srv/jekyll
   WORKDIR /srv/jekyll
   RUN bundle install
   EXPOSE 4000
   CMD ["jekyll", "serve", "--host", "0.0.0.0", "--livereload"]
   ```

2. **Build and run**:
   ```bash
   docker build -t windows95-blog .
   docker run -p 4000:4000 windows95-blog
   ```

### Method 2: Using rbenv/rvm (Ruby Version Manager)

1. **Install rbenv**:
   ```bash
   # On Arch Linux
   sudo pacman -S rbenv ruby-build
   
   # Initialize rbenv
   echo 'export PATH="$HOME/.rbenv/bin:$PATH"' >> ~/.bashrc
   echo 'eval "$(rbenv init -)"' >> ~/.bashrc
   source ~/.bashrc
   ```

2. **Install Ruby**:
   ```bash
   rbenv install 3.1.0
   rbenv global 3.1.0
   ```

3. **Install gems**:
   ```bash
   gem install bundler
   bundle install
   ```

### Method 3: Using User-local Installation

1. **Install gems to user directory**:
   ```bash
   bundle install --path vendor/bundle
   ```

2. **Run with bundle exec**:
   ```bash
   bundle exec jekyll serve --livereload
   ```

### Method 4: GitHub Codespaces / GitPod

1. **Push to GitHub**
2. **Open in Codespaces** (free tier available)
3. **Run in cloud environment**:
   ```bash
   bundle install
   bundle exec jekyll serve --livereload
   ```

## GitHub Pages Deployment

### Automatic Deployment

1. **Create `.github/workflows/jekyll.yml`**:
   ```yaml
   name: Deploy Jekyll site to Pages
   
   on:
     push:
       branches: [ main ]
   
   permissions:
     contents: read
     pages: write
     id-token: write
   
   concurrency:
     group: "pages"
     cancel-in-progress: false
   
   jobs:
     build:
       runs-on: ubuntu-latest
       steps:
         - name: Checkout
           uses: actions/checkout@v4
         - name: Setup Ruby
           uses: ruby/setup-ruby@v1
           with:
             ruby-version: '3.1'
             bundler-cache: true
         - name: Setup Pages
           uses: actions/configure-pages@v4
         - name: Build with Jekyll
           run: bundle exec jekyll build --baseurl "${{ steps.pages.outputs.base_path }}"
           env:
             JEKYLL_ENV: production
         - name: Upload artifact
           uses: actions/upload-pages-artifact@v3
           with:
             path: ./_site
   
     deploy:
       environment:
         name: github-pages
         url: ${{ steps.deployment.outputs.page_url }}
       runs-on: ubuntu-latest
       needs: build
       steps:
         - name: Deploy to GitHub Pages
           id: deployment
           uses: actions/deploy-pages@v4
   ```

2. **Enable GitHub Pages**:
   - Go to repository Settings → Pages
   - Select "GitHub Actions" as source
   - The site will be available at `https://yourusername.github.io/repository-name`

### Manual Deployment

1. **Build the site**:
   ```bash
   bundle exec jekyll build
   ```

2. **Upload `_site` folder** to your hosting provider:
   - **Netlify**: Drag and drop the `_site` folder
   - **Vercel**: Import repository and set build command to `bundle exec jekyll build`
   - **AWS S3**: Upload to S3 bucket with static hosting enabled

## Troubleshooting

### Common Issues

**Permission denied errors**:
- Use Docker or rbenv/rvm for isolated Ruby environment
- Install gems to user directory with `--path vendor/bundle`

**Jekyll not found**:
- Ensure you're using `bundle exec jekyll` instead of just `jekyll`
- Check that all dependencies are installed

**Build failures**:
- Verify YAML syntax in `_config.yml`
- Check that all required files exist
- Ensure markdown files have proper front matter

**Search not working**:
- Verify `search.json` is generated in `_site` folder
- Check browser console for JavaScript errors
- Ensure posts have proper categories and content

### Getting Help

- Check [Jekyll documentation](https://jekyllrb.com/docs/)
- Review [GitHub Pages documentation](https://docs.github.com/en/pages)
- Open an issue in the repository for specific problems

---

The Windows 95 Blog is ready to deploy! Choose the method that works best for your environment.
