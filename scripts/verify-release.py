#!/usr/bin/env python3
"""Validate metadata and public-key signatures without reading private keys."""
import json, pathlib, plistlib, subprocess, sys, xml.etree.ElementTree as ET
root = pathlib.Path(__file__).resolve().parents[1]
folder = pathlib.Path(sys.argv[1]).resolve()
c = json.loads((root / 'Config/updates.json').read_text())
sparkle = '{http://www.andymatuschak.org/xml-namespaces/sparkle}'
items = ET.parse(folder/'appcast.xml').findall('./channel/item')
assert len(items) == 1, 'Expected one release in the generated feed'
item = items[0]
enclosure = item.find('enclosure')
assert item.findtext(sparkle+'version') == c['build']
archive = folder / ('CorsoShield-' + c['version'] + '.zip')
assert enclosure.attrib['url'] == 'https://github.com/' + c['repository'] + '/releases/download/v' + c['version'] + '/' + archive.name
assert int(enclosure.attrib['length']) == archive.stat().st_size
signature = enclosure.attrib[sparkle+'edSignature']
subprocess.run(['swift', '-module-cache-path', str(root/'.build/clang-cache'), str(root/'scripts/verify-archive.swift'), str(archive), signature, c['publicKey']], check=True)
# A modified archive must be rejected before any extraction or execution.
tampered = root/'.build/tampered-update.bin'
try:
    data = bytearray(archive.read_bytes()); data[len(data)//2] ^= 1; tampered.write_bytes(data)
    result = subprocess.run(['swift', '-module-cache-path', str(root/'.build/clang-cache'), str(root/'scripts/verify-archive.swift'), str(tampered), signature, c['publicKey']], capture_output=True)
    assert result.returncode != 0, 'Modified update was incorrectly accepted'
finally:
    tampered.unlink(missing_ok=True)
plist = plistlib.load(open(root/'dist/Corso Shield.app/Contents/Info.plist','rb'))
assert plist['SUPublicEDKey'] == c['publicKey']
assert plist['SURequireSignedFeed'] and plist['SUVerifyUpdateBeforeExtraction']
assert plist['CFBundleVersion'] == c['build']
print('PASS: release URLs, versions, length, pinned-key archive signature and tamper rejection')
