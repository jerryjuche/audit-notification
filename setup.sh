#!/bin/bash

# Audit Notification System - Setup Script
# Initializes the project for first-time use

set -e

echo "🔔 Audit Notification System - Setup"
echo "===================================="
echo ""

# Check Go installation
if ! command -v go &> /dev/null; then
    echo "❌ Go is not installed. Please install Go 1.21+ first."
    echo "   Visit: https://go.dev/dl/"
    exit 1
fi

echo "✅ Go version: $(go version)"
echo ""

# Check if go.mod exists
if [ ! -f "go.mod" ]; then
    echo "❌ go.mod not found. Are you in the project root?"
    exit 1
fi

# Install dependencies
echo "📦 Installing dependencies..."
go mod download
go mod tidy
echo "✅ Dependencies installed"
echo ""

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p bin
mkdir -p client
mkdir -p data
echo "✅ Directories created"
echo ""

# Setup environment file
if [ ! -f ".env" ]; then
    echo "⚙️  Creating .env file..."
    cp .env.example .env
    echo "✅ .env created (edit if needed)"
else
    echo "ℹ️  .env already exists"
fi
echo ""

# Build the project
echo "🔨 Building server..."
go build -o bin/audit-server cmd/server/main.go
echo "✅ Server built successfully"
echo ""

echo "======================================"
echo "✅ Setup complete!"
echo ""
echo "Quick start:"
echo "  1. Run:    go run cmd/server/main.go"
echo "  2. Open:   http://localhost:8080"
echo "  3. Test with users: jerry, admin, test"
echo ""
echo "Or use Make:"
echo "  make run     # Start server"
echo "  make help    # Show all commands"
echo ""
echo "Need help? Read QUICKSTART.md"
echo "======================================"
