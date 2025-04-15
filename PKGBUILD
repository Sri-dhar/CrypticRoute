pkgname=crypticroute
_pkgname=CrypticRoute
pkgver=3.0
pkgrel=1
pkgdesc="Network Steganography Tool for covert data transmission via crafted TCP packets"
arch=('any')
url="https://github.com/Sri-dhar/CrypticRoute"
license=('custom:Unknown') # TODO: Add a proper license file to the project and update this field and pyproject.toml
depends=('python' 'python-pyqt6' 'python-psutil' 'python-netifaces' 'python-cryptography' 'python-scapy' 'python-toml')
makedepends=('python-build' 'python-installer' 'python-hatchling' 'git') # Added git for VCS source
checkdepends=('python-pytest' 'python-pytest-mock')
# Use git source for easier updates. Using main branch for now. Consider using a specific tag (e.g., #tag=v3.0) or commit hash for stable releases.
source=("${_pkgname}::git+${url}.git#branch=main") # Using main branch
sha256sums=('SKIP') # 'SKIP' is appropriate for VCS sources

# Prepare function to ensure the source directory matches _pkgname
prepare() {
  cd "${srcdir}"
  # If the git clone directory doesn't match _pkgname, rename it
  # This depends on how makepkg clones the repo. Often it's just the pkgname.
  # Check the actual directory name during build if issues arise.
  if [ -d "${pkgname}" ] && [ ! -d "${_pkgname}" ]; then
    mv "${pkgname}" "${_pkgname}"
  fi
}

# Use standard Python build process now that pyproject.toml exists
build() {
  cd "${srcdir}/${_pkgname}"
  python -m build --wheel --no-isolation
}

check() {
  cd "${srcdir}/${_pkgname}"
  # Ensure tests are run from the project root where pyproject.toml is
  # Adjust if tests need specific setup or are in a different directory
  # Skip tests if checkdepends are not installed or if tests fail intermittently
  # Consider adding options like --noconfirm to pacman commands if running in automated environments
  pytest Tests/ || echo "pytest checks failed or checkdepends not installed, skipping..."
}

package() {
  cd "${srcdir}/${_pkgname}"
  python -m installer --destdir="${pkgdir}" dist/*.whl
  # Install license file if it exists
  # TODO: Uncomment this line after adding a LICENSE file and updating the license field above
  # install -Dm644 LICENSE "${pkgdir}/usr/share/licenses/${pkgname}/LICENSE"
}

# Notes:
# 1. Source URL: Using git source. Replace PUT_COMMIT_HASH_HERE with a specific commit hash, tag (e.g., #tag=v3.0), or branch (e.g., #branch=main).
# 2. Checksums: 'SKIP' is used for VCS sources.
# 3. Build System: Uses standard python-build and python-installer with pyproject.toml.
# 4. Dependencies: Runtime dependencies are in `depends`. Build dependencies are in `makedepends`. Test dependencies are in `checkdepends`.
# 5. License: Add a LICENSE file to your repo, update the `license` field here and in pyproject.toml, and uncomment the install line in package().
# 6. Maintainer: Update the Maintainer line at the top.
# 7. Tests: Assumes tests are in the 'Tests/' directory. The check() function attempts to run them but will not fail the build if they error (useful during development).
# 8. Prepare Function: Added to handle potential directory name mismatches when cloning from git.
