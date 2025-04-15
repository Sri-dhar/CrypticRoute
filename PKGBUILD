pkgname=crypticroute
pkgver=1.3
pkgrel=1
pkgdesc="Network steganography tool designed to transmit data covertly by embedding it within crafted TCP packets."
arch=('any')
url="https://github.com/Sri-dhar/CrypticRoute" 
license=('custom') 
depends=(
    'python'
    'python-pyqt6'
    'python-psutil'
    'python-netifaces'
    'python-cryptography'
    'python-scapy'
)
provides=('crypticroute_cli' 'crypticroute_gui')
conflicts=()
# Use a placeholder URL for the source tarball. Replace with the actual URL for v1.3.
# config.toml is included as a local source file.
_pkgname_lower=${pkgname,,} # Get lowercase pkgname for source URL (assuming repo name matches pkgname)
source=("${_pkgname_lower}-${pkgver}.tar.gz::https://github.com/Sri-dhar/CrypticRoute/archive/refs/tags/v${pkgver}.tar.gz"
        "config.toml")
sha256sums=('sha256sum_placeholder' # Replace with actual checksum for the tarball
            'SKIP') # SKIP for local config.toml

build() {
    # Assuming the source tarball extracts to a directory named CrypticRoute-1.3 or similar
    # Adjust the path if the extracted directory name is different
    cd "${srcdir}/${pkgname}-${pkgver}"
    # Ensure the main scripts are executable
    chmod +x crypticroute_cli.py crypticroute_gui.py
}

package() {
    local install_dir="${pkgdir}/usr/share/${pkgname}"
    # Assuming the source tarball extracts to a directory named CrypticRoute-1.3 or similar
    # Adjust the path if the extracted directory name is different
    local source_root="${srcdir}/${pkgname}-${pkgver}"

    # Install main scripts
    install -Dm755 "${source_root}/crypticroute_cli.py" "${install_dir}/crypticroute_cli.py"
    install -Dm755 "${source_root}/crypticroute_gui.py" "${install_dir}/crypticroute_gui.py"

    # Install the crypticroute library directory
    cp -r "${source_root}/crypticroute" "${install_dir}/crypticroute"
    # Install the gui library directory
    cp -r "${source_root}/gui" "${install_dir}/gui"

    # Install config.toml (from local source)
    install -Dm644 "${srcdir}/config.toml" "${install_dir}/config.toml"

    # Create symbolic links in /usr/bin pointing to the installed scripts
    # These links will allow running 'crypticroute_cli' and 'crypticroute_gui' directly
    ln -sf "/usr/share/${pkgname}/crypticroute_cli.py" "${pkgdir}/usr/bin/crypticroute_cli"
    ln -sf "/usr/share/${pkgname}/crypticroute_gui.py" "${pkgdir}/usr/bin/crypticroute_gui"
}
