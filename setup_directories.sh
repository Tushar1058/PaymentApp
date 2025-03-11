#!/bin/bash

# Create main directories
mkdir -p static/screenshots
mkdir -p static/qr_codes
mkdir -p database

# Create .gitkeep files to track empty directories
touch static/screenshots/.gitkeep
touch static/qr_codes/.gitkeep
touch database/.gitkeep

# Set permissions
chmod -R 755 static
chmod -R 755 database

echo "Directory structure created successfully!" 