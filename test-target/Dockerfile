FROM python:3.11-slim

WORKDIR /app

# Install dependencies
RUN pip install --no-cache-dir flask

# Copy application files
COPY app.py .
COPY templates/ templates/

# Create uploads directory
RUN mkdir -p uploads

# Create a fake .git directory for information disclosure vulnerability
RUN mkdir -p .git && \
    echo '[core]' > .git/config && \
    echo '    repositoryformatversion = 0' >> .git/config && \
    echo '    filemode = true' >> .git/config && \
    echo '    bare = false' >> .git/config && \
    echo '    logallrefupdates = true' >> .git/config && \
    echo '[remote "origin"]' >> .git/config && \
    echo '    url = https://github.com/vulnerable/app.git' >> .git/config && \
    echo '    fetch = +refs/heads/*:refs/remotes/origin/*' >> .git/config

# Expose port
EXPOSE 5000

# Run the application
CMD ["python", "app.py"]