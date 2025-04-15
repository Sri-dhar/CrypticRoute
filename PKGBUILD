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
source=("dist/crypticroute_cli" "dist/crypticroute_gui" "config.toml")
noextract=()
sha256sums=('SKIP' 'SKIP' 'SKIP') 

package() {
    local install_dir="${pkgdir}/usr/share/${pkgname}"
    install -d "${install_dir}"
    install -Dm755 "${srcdir}/crypticroute_cli" "${install_dir}/crypticroute_cli"
    install -Dm755 "${srcdir}/crypticroute_gui" "${install_dir}/crypticroute_gui"
    install -Dm644 "${srcdir}/config.toml" "${install_dir}/config.toml"

    ln -sf "/usr/share/${pkgname}/crypticroute_cli" "${pkgdir}/usr/bin/crypticroute_cli"
    ln -sf "/usr/share/${pkgname}/crypticroute_gui" "${pkgdir}/usr/bin/crypticroute_gui"

}
