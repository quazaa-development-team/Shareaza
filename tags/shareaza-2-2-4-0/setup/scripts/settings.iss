; This sub-script lists all Shareaza settings that have to be written at installation time

[Registry]
; Set speed rates in byte/sec
Root: HKCU; Subkey: "Software\Shareaza\Shareaza\Settings"; ValueType: dword; ValueName: "RatesInBytes"; ValueData: "{ini:{param:SETTINGS|},General,RatesInBytes|1}"; Flags: createvalueifdoesntexist uninsdeletekey
; Turn off verbose mode in network tab
Root: HKCU; Subkey: "Software\Shareaza\Shareaza\Settings"; ValueType: dword; ValueName: "VerboseMode"; ValueData: "{ini:{param:SETTINGS|},General,VerboseMode|0}"; Flags: createvalueifdoesntexist uninsdeletekey
; Turn on ShareazaOS skin
Root: HKCU; Subkey: "Software\Shareaza\Shareaza\Skins"; ValueType: dword; ValueName: "ShareazaOS\ShareazaOS.xml"; ValueData: "{ini:{param:SETTINGS|},Skins,ShareazaOS|1}"; Flags: createvalueifdoesntexist uninsdeletekey
; Disable extensions for plugins which make trouble
; Since it is image services plugin we need to add extensions required for the first run
Root: HKCU; Subkey: "Software\Shareaza\Shareaza\Plugins"; ValueType: string; ValueName: "{{FF5FCD00-2C20-49D8-84F6-888D2E2C95DA}"; ValueData: "|-.pdf||.bmp||.png||.jpg|"; Flags: createvalueifdoesntexist uninsdeletekey

