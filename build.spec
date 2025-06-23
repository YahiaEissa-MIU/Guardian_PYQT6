# build.spec  –  Guardian-2.2  (PyQt6 edition, “kitchen-sink”)

from pathlib import Path
from PyInstaller.utils.hooks import (
    collect_all,
    collect_data_files,
    collect_submodules,
)

# ───────────────────────────────────────────────────────────────
# 1. 3rd-party helper bundles
# ───────────────────────────────────────────────────────────────
req_data,   req_bins,   req_hidden   = collect_all('requests')
psutil_data,psutil_bins,psutil_hidden= collect_all('psutil')

# PyQt6 – grab *everything* that exists in the venv
pyqt_data       = collect_data_files('PyQt6', include_py_files=True)
pyqt_submodules = collect_submodules('PyQt6')

# → Charts lives in its own wheel; wrap in try/except so build
#   still works when the wheel is absent.
try:
    pyqt_data       += collect_data_files('PyQt6.QtCharts')
    pyqt_submodules += collect_submodules('PyQt6.QtCharts')
except ModuleNotFoundError:
    print('*** PyQt6-Charts wheel not found – install it if you need charts. ***')

# ───────────────────────────────────────────────────────────────
# 2.  admin manifest  (unchanged)
# ───────────────────────────────────────────────────────────────
admin_manifest = r"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity version="1.0.0.0" processorArchitecture="X86"
                    name="Guardian" type="win32"/>
  <description>Guardian Security Application</description>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
    </application>
  </compatibility>
</assembly>"""

# ───────────────────────────────────────────────────────────────
# 3.  data / binaries / hidden-imports
# ───────────────────────────────────────────────────────────────
datas = (
      req_data
    + psutil_data
    + pyqt_data
    + [
        ('views',        'views'),
        ('models',       'models'),
        ('controllers',  'controllers'),
        ('utils',        'utils'),
        ('services',     'services'),
      ]
)

hiddenimports = [
    'PyQt6',
    'PyQt6.QtCore',
    'PyQt6.QtGui',
    'PyQt6.QtWidgets',
    'PyQt6.QtNetwork',
    'PyQt6.QtCharts',

    'aiohttp',
    'asyncio',
    'asyncio.windows_events',
    'requests',
    'urllib3',
    'charset_normalizer',
    'idna',
    'certifi',
    'psutil',
    'plyer.platforms.win.notification',
    'reportlab',
    'csv',
    'json',
    'subprocess',
    'logging',
    'threading',
    'os',
    'sys',
    'datetime',
    'ctypes',
    'xml.etree.ElementTree',
    'PIL',
    'PIL.Image',
    'PIL.ImageQt',
    'bs4',                  # beautifulsoup if used
    'lxml',                 # if used in bs4 parser
    'Crypto',              # if you use pycryptodome
    'win32com', 'win32com.client'  # if you use pywin32 stuff
]

binaries = req_bins + psutil_bins

# ───────────────────────────────────────────────────────────────
# 4.  Analysis → EXE
# ───────────────────────────────────────────────────────────────
block_cipher = None
a = Analysis(
    ['main.py'],
    pathex=[str(Path.cwd())],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

# extra run-time data file your app expects
a.datas += [('acknowledged_alerts.txt', '', 'DATA')]

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='Guardian_v2.2',
    debug=False,
    strip=False,
    upx=True,
    console=False,           # set True for a debug console
    manifest=admin_manifest,
    uac_admin=True,
    # icon='assets\\Guardian.ico',
)
