#!/bin/zsh
set -euo pipefail

if [[ $# -ne 3 ]]; then
  print -u2 "usage: $0 <JailbreakLab.app> <jailbreaklab-helper> <JailbreakLabShadow.dylib>"
  exit 64
fi

app_path=$1
helper_path=$2
injection_path=$3
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
[[ -f "${injection_path}" ]] || { print -u2 "injection dylib not found: ${injection_path}"; exit 66; }
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
  local injection_directory="${stage}${prefix}/Library/MobileSubstrate/DynamicLibraries"
  local installed_app="${prefix}/Applications/JailbreakLab.app"
  local installed_helper="${prefix}/usr/local/libexec/jailbreaklab-helper"

  rm -rf "${stage}"
  mkdir -p "${application_directory}" "${helper_directory}" "${injection_directory}" "${stage}/DEBIAN"
  cp -R "${app_path}" "${application_directory}/JailbreakLab.app"
  cp "${helper_path}" "${helper_directory}/jailbreaklab-helper"
  cp "${injection_path}" "${injection_directory}/JailbreakLabShadow.dylib"
  chmod 0755 "${helper_directory}/jailbreaklab-helper"

  ldid -S"${project_root}/App/Resources/JailbreakLab.entitlements" "${application_directory}/JailbreakLab.app/JailbreakLab"
  ldid -S"${project_root}/Helper/entitlements.plist" "${helper_directory}/jailbreaklab-helper"
  ldid -S "${injection_directory}/JailbreakLabShadow.dylib"

  cat > "${stage}/DEBIAN/control" <<CONTROL
Package: com.securitylab.jailbreaklab.${scheme}
Name: Jailbreak Lab (${scheme})
Version: 1.7.0
Architecture: ${architecture}
Depends: mobilesubstrate
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
if [ -f /private/var/db/jailbreaklab/shadow-target-state-v2 ]; then
  '${installed_helper}' --operation enable-objc-class --root-mode auto --groups jailbreak-markers --live >/dev/null 2>&1 || true
else
  '${installed_helper}' --operation disable-objc-class --root-mode auto --groups jailbreak-markers --live >/dev/null 2>&1 || true
fi
uicache -p '${installed_app}' >/dev/null 2>&1 || true
exit 0
POSTINST
  chmod 0755 "${stage}/DEBIAN/postinst"

  cat > "${stage}/DEBIAN/prerm" <<PRERM
#!/bin/sh
case "\${1:-}" in
  remove|deconfigure)
    '${installed_helper}' --operation disable-objc-class --root-mode auto --groups jailbreak-markers --live >/dev/null 2>&1 || true
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

  local output="${package_root}/com.securitylab.jailbreaklab_1.7.0_${scheme}.deb"
  dpkg-deb --root-owner-group --build "${stage}" "${output}"
  print "created ${output}"
}

build_package rootless
build_package rootful
