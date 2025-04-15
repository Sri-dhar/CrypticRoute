# Maintainer: Your Name <your email@domain.com>
# Contributor: Cline <AI Assistant>

pkgname=crypticroute
pkgver=1.3
pkgrel=1
pkgdesc="Network steganography tool designed to transmit data covertly by embedding it within crafted TCP packets."
arch=('any')
url="https://github.com/Sri-dhar/CrypticRoute" # No project URL provided
license=('custom') # User indicated no specific license
depends=(
    'python'
    'python-pyqt6'
    'python-psutil'
    'python-netifaces'
    'python-cryptography'
    'python-scapy'
)
# Provides the command names
provides=('crypticroute_cli' 'crypticroute_gui')
# Conflicts with older versions if they existed under a different name
conflicts=()
# The source is the local dist directory containing the binaries
source=("dist/crypticroute_cli" "dist/crypticroute_gui")
# No checksums needed for local sources
noextract=()
sha256sums=('SKIP' 'SKIP') # SKIP for local files

package() {
    # Install the binaries to /usr/bin
    install -Dm755 "${srcdir}/crypticroute_cli" "${pkgdir}/usr/bin/crypticroute_cli"
    install -Dm755 "${srcdir}/crypticroute_gui" "${pkgdir}/usr/bin/crypticroute_gui"

    # Note: This PKGBUILD assumes the binaries in 'dist/' are ready to run
    # and have the necessary Python shebang or are standalone executables.
    # It also assumes they find their dependencies correctly when installed system-wide.
    # If the application relies on relative paths to other project files (like config.toml),
    # those would also need to be installed (e.g., to /usr/share/crypticroute) and the
    # scripts potentially modified to find them.
}
