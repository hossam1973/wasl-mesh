require 'json'
package = JSON.parse(File.read(File.join(__dir__, 'package.json')))

Pod::Spec.new do |s|
  s.name = 'WaslNearby'
  s.version = package['version']
  s.summary = package['description']
  s.license = package['license']
  s.homepage = 'https://github.com/hossam1973/wasl-mesh'
  s.author = 'Wasl'
  s.source = { :git => 'https://github.com/hossam1973/wasl-mesh.git', :tag => s.version.to_s }
  s.source_files = 'ios/Sources/**/*.{swift,h,m}'
  s.ios.deployment_target = '13.0'
  s.frameworks = 'MultipeerConnectivity'
  s.dependency 'Capacitor'
  s.swift_version = '5.1'
end
