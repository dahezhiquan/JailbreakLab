#!/bin/zsh
set -euo pipefail

if [[ $# -ne 2 ]]; then
  print -u2 "usage: $0 <JailbreakLab.app> <jailbreaklab-helper>"
  exit 64
fi

app_path=$1
helper_path=$2
project_root=${0:A:h:h}
package_root="${project_root}/Packages"

for dependency in ldid dpkg-deb; do
  command -v "${dependency}" >/dev/null || {
    print -u2 "missing dependency: ${dependency}"
    exit 69
  }
done

[[ -d "${app_path}" ]] || { print -u2 "app not found: ${app_path}"; exit 66; }
[[ -f "${helper_path}" ]] || { print -u2 "helper not found: ${helper_path}"; exit 66; }
mkdir -p "${package_root}"

build_package() {
  local scheme=$1
  local stage="${project_root}/build/package-${scheme}"
  local prefix=""
  local architecture="iphoneos-arm"

  if [[ "${scheme}" == "rootless" ]]; then
    prefix="/var/jb"
    architecture="iphoneos-arm64"
  fi

  local application_directory="${stage}${prefix}/Applications"
  local helper_directory="${stage}${prefix}/usr/local/libexec"
  local installed_app="${prefix}/Applications/JailbreakLab.app"
  local installed_helper="${prefix}/usr/local/libexec/jailbreaklab-helper"

  rm -rf "${stage}"
  mkdir -p "${application_directory}" "${helper_directory}" "${stage}/DEBIAN"
  cp -R "${app_path}" "${application_directory}/JailbreakLab.app"
  cp "${helper_path}" "${helper_directory}/jailbreaklab-helper"
  chmod 0755 "${helper_directory}/jailbreaklab-helper"

  ldid -S"${project_root}/App/Resources/JailbreakLab.entitlements" "${application_directory}/JailbreakLab.app/JailbreakLab"
  ldid -S"${project_root}/Helper/entitlements.plist" "${helper_directory}/jailbreaklab-helper"

  cat > "${stage}/DEBIAN/control" <<CONTROL
Package: com.securitylab.jailbreaklab.${scheme}
Name: Jailbreak Lab (${scheme})
Version: 1.4.1
Architecture: ${architecture}
Description: Controlled jailbreak artifact simulator for owned security test devices.
Maintainer: Security Lab
Author: Security Lab
Section: Utilities
Priority: optional
Conflicts: com.securitylab.jailbreaklab.rootful, com.securitylab.jailbreaklab.rootless
CONTROL

  cat > "${stage}/DEBIAN/postinst" <<POSTINST
#!/bin/sh
set -e
chown root:wheel '${installed_helper}'
chmod 4755 '${installed_helper}'
uicache -p '${installed_app}' >/dev/null 2>&1 || true
exit 0
POSTINST
  chmod 0755 "${stage}/DEBIAN/postinst"

  cat > "${stage}/DEBIAN/prerm" <<PRERM
#!/bin/sh
case "\${1:-}" in
  remove|deconfigure)
    '${installed_helper}' --operation disable-symlinks --root-mode auto --groups jailbreak-markers --live >/dev/null 2>&1 || true
    '${installed_helper}' --operation disable-write-remove --root-mode auto --groups jailbreak-markers --live >/dev/null 2>&1 || true
    ;;
esac
exit 0
PRERM
  chmod 0755 "${stage}/DEBIAN/prerm"

  cat > "${stage}/DEBIAN/postrm" <<'POSTRM'
#!/bin/sh
uicache -u com.securitylab.jailbreaklab >/dev/null 2>&1 || true
exit 0
POSTRM
  chmod 0755 "${stage}/DEBIAN/postrm"

  local output="${package_root}/com.securitylab.jailbreaklab_1.4.1_${scheme}.deb"
  dpkg-deb --root-owner-group --build "${stage}" "${output}"
  print "created ${output}"
}

build_package rootless
build_package rootful
