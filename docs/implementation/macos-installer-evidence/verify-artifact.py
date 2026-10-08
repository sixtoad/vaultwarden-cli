import pathlib,subprocess,plistlib,hashlib,json,os,shutil,sys,datetime
root=pathlib.Path(sys.argv[1]).resolve()
output=root/'output'
images=list(output.glob('*.dmg')); assert len(images)==1, images
image=images[0]
subprocess.run(['/usr/bin/hdiutil','verify',str(image)],check=True)
info=plistlib.loads(subprocess.check_output(['/usr/bin/hdiutil','imageinfo','-plist',str(image)]))
assert info['Format']=='UDZO',info.get('Format')
mount=root/'verification-mount'; mount.mkdir()
attached=False
try:
 subprocess.run(['/usr/bin/hdiutil','attach','-readonly','-nobrowse','-noautoopen','-mountpoint',str(mount),str(image)],check=True)
 attached=True
 assert os.statvfs(mount).f_flag & os.ST_RDONLY
 assert (mount/'Applications').is_symlink() and os.readlink(mount/'Applications')=='/Applications'
 app=mount/'Approval Companion.app'; executable=app/'Contents/MacOS/ApprovalCompanion'
 subprocess.run(['/usr/bin/codesign','--verify','--strict',str(app)],check=True)
 plist=plistlib.loads((app/'Contents/Info.plist').read_bytes())
 assert plist['CFBundleIdentifier']=='dev.vaultwarden.ApprovalCompanion'
 assert plist['LSMinimumSystemVersion']=='13.0'
 assert plist['NSAppTransportSecurity']=={'NSAllowsArbitraryLoads':True}
 arch=subprocess.check_output(['/usr/bin/lipo','-archs',str(executable)],text=True).strip(); assert arch=='arm64'
 dependencies=subprocess.check_output(['/usr/bin/otool','-L',str(executable)],text=True)
 for line in dependencies.splitlines()[1:]:
  dep=line.strip().split(' (',1)[0]
  assert dep.startswith(('/usr/lib/','/System/Library/')),dep
 copied=root/'disposable-installation/Approval Companion.app'
 copied.parent.mkdir()
 subprocess.run(['/usr/bin/ditto',str(app),str(copied)],check=True)
 subprocess.run(['/usr/bin/codesign','--verify','--strict',str(copied)],check=True)
 hashes={}
 for file in app.rglob('*'):
  relative=file.relative_to(app)
  if file.is_file():
   assert not file.is_symlink()
   data=file.read_bytes(); assert (copied/relative).read_bytes()==data
   assert b'-----BEGIN PRIVATE KEY-----' not in data
   hashes[str(relative)]=hashlib.sha256(data).hexdigest()
 names=[p.name for p in mount.iterdir()]
 report={'verified_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'image':image.name,'image_sha256':hashlib.sha256(image.read_bytes()).hexdigest(),'image_bytes':image.stat().st_size,'format':'UDZO','mounted_read_only':True,'volume_entries':names,'architecture':arch,'version':plist['CFBundleShortVersionString'],'minimum_macos':plist['LSMinimumSystemVersion'],'strict_signature_verified':True,'copied_app_matches_every_file':True,'system_dependencies_only':True,'app_file_hashes':hashes,'installed_app_or_preferences_changed':False,'app_launched':False,'notarized':False}
finally:
 if attached: subprocess.run(['/usr/bin/hdiutil','detach',str(mount)],check=True)
 mount.rmdir()
report['detached']=True
(root/'verification.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
