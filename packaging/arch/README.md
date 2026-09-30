# Arch Linux: Goodix 27c6:55a2

This package builds the `new` branch with all drivers, including the custom
Goodix 55a2 driver. It provides `libfprint` and `libfprint-2.so` for `fprintd`,
and replaces the official `libfprint` package through pacman. Its distinct
package name keeps ordinary repository upgrades from overwriting the driver.

## Build and install

```sh
sudo pacman -S --needed base-devel git meson ninja gobject-introspection python-gobject python-cairo
git clone --branch new https://github.com/ElvinStarry/libfprint.git
cd libfprint/packaging/arch
makepkg -si
sudo systemd-hwdb update
sudo udevadm control --reload
sudo udevadm trigger --subsystem-match=usb --attr-match=idVendor=27c6 --attr-match=idProduct=55a2
sudo systemctl restart fprintd
fprintd-list "$USER"
fprintd-verify
```

`makepkg` runs the project's tests. Driver replay tests require the optional
`umockdev` package; Meson reports those tests as skipped when it is absent.

For subsequent driver updates, pull this branch and rebuild the package with
`makepkg -sif` in this directory. Keep the installed package managed by pacman.

## Clean build artifacts

After installation, remove `src/`, `pkg/`, the cached `libfprint/` Git clone,
and the generated `*.pkg.tar.zst` files from this directory. The project source
and `PKGBUILD` remain available for the next rebuild.
