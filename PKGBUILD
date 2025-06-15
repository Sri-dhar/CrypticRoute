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
_pkgname_lower=${pkgname,,}
source=("${_pkgname_lower}-${pkgver}.tar.gz::https://github.com/Sri-dhar/CrypticRoute/archive/refs/tags/v${pkgver}.tar.gz"
        "config.toml")
sha256sums=('sha256sum_placeholder'
            'SKIP') 

build() {
    cd "${srcdir}/${pkgname}-${pkgver}"
    chmod +x crypticroute_cli.py crypticroute_gui.py
}

package() {
    local install_dir="${pkgdir}/usr/share/${pkgname}"
    local source_root="${srcdir}/${pkgname}-${pkgver}"

    install -Dm755 "${source_root}/crypticroute_cli.py" "${install_dir}/crypticroute_cli.py"
    install -Dm755 "${source_root}/crypticroute_gui.py" "${install_dir}/crypticroute_gui.py"

    cp -r "${source_root}/crypticroute" "${install_dir}/crypticroute"
    cp -r "${source_root}/gui" "${install_dir}/gui"

    install -Dm644 "${srcdir}/config.toml" "${install_dir}/config.toml"

    ln -sf "/usr/share/${pkgname}/crypticroute_cli.py" "${pkgdir}/usr/bin/crypticroute_cli"
    ln -sf "/usr/share/${pkgname}/crypticroute_gui.py" "${pkgdir}/usr/bin/crypticroute_gui"
}
