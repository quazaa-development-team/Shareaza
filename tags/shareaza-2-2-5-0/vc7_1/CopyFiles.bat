if not exist %1 mkdir %1
if not exist %1\Data mkdir %1\Data
xcopy ..\Data\*.* %1\Data /e /y /q
if not exist %1\Remote mkdir %1\Remote
xcopy ..\Remote\*.* %1\Remote /e /y /q
if not exist %1\Schemas mkdir %1\Schemas
xcopy ..\Schemas\*.* %1\Schemas /e /y /q
if not exist %1\Skins mkdir %1\Skins
xcopy ..\Skins\*,* %1\Skins /e /y /q
if not exist %1\Skins\Languages mkdir %1\Skins\Languages
xcopy ..\Languages\*.* %1\Skins\Languages /e /y /q