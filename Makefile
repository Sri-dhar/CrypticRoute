# Makefile for the CrypticRoute project

# Use fish shell for commands if available, otherwise default shell
SHELL := /usr/bin/env fish

# Define Python interpreter
PYTHON := python3

# Define source files (optional, but good practice)
SOURCES := $(shell find crypticroute gui Tests -name '*.py')

.PHONY: help install run-cli run-gui test build-docker build-pkg clean

help:
	@echo "Available targets:"
	@echo "  install      - Install project dependencies from requirements.txt"
	@echo "  run-cli      - Run the CrypticRoute Command Line Interface"
	@echo "  run-gui      - Run the CrypticRoute Graphical User Interface"
	@echo "  test         - Run pytest tests"
	@echo "  build-docker - Build the Docker image"
	@echo "  build-pkg    - Build the Arch Linux package (requires makepkg)"
	@echo "  clean        - Remove __pycache__ directories and build artifacts"

install: requirements.txt
	@echo "Installing dependencies..."
	$(PYTHON) -m pip install -r requirements.txt

run-cli:
	@echo "Running CrypticRoute CLI..."
	$(PYTHON) crypticroute_cli.py

run-gui:
	@echo "Running CrypticRoute GUI..."
	$(PYTHON) crypticroute_gui.py

test:
	@echo "Running tests..."
	$(PYTHON) -m pytest Tests/

build-docker: Dockerfile
	@echo "Building Docker image..."
	docker build -t crypticroute .

build-pkg: PKGBUILD .SRCINFO
	@echo "Building Arch Linux package..."
	@echo "Note: This may require user interaction and sudo privileges."
	makepkg -si

clean:
	@echo "Cleaning up..."
	find . -type f -name '*.py[co]' -delete
	find . -type d -name '__pycache__' -delete
	rm -rf build dist *.egg-info crypticroute-*.pkg.tar.zst
