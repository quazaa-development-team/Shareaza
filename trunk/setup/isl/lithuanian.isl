; *** Inno Setup version 4.2.2+ Lithuanian messages ***
;
; To download user-contributed translations of this file, go to:
;   http://www.jrsoftware.org/is3rdparty.php
;
; Note: When translating this text, do not add periods (.) to the end of
; messages that didn't have them already, because on those messages Inno
; Setup adds the periods automatically (appending a period would result in
; two periods being displayed).
;
; $jrsoftware: issrc/Files/Lithuanian.isl,v 1.00 2004/06/19 $
; Translated by Robertas Rimas (Loptar@takas.lt)

[LangOptions]
LanguageName=Lithuanian
LanguageID=$0427
LanguageCodePage=1257
; If the language you are translating to requires special font faces or
; sizes, uncomment any of the following entries and change them accordingly.
DialogFontName=Tahoma
DialogFontSize=8
WelcomeFontName=Tahoma
WelcomeFontSize=12
TitleFontName=Tahoma
TitleFontSize=24
CopyrightFontName=Tahoma
CopyrightFontSize=8

[Messages]

; *** Application titles
SetupAppTitle=�diegimas
SetupWindowTitle=�diegimas - %1
UninstallAppTitle=Pa�alinimas
UninstallAppFullTitle=%1 Pa�alinimas

; *** Misc. common
InformationTitle=Informacija
ConfirmTitle=Patvirtinimas
ErrorTitle=Klaida

; *** SetupLdr messages
SetupLdrStartupMessage=%1 �diegimas. Ar norite t�sti?
LdrCannotCreateTemp=Negaliu sukurti laikin� fail�. �diegimas nutraukiamas
LdrCannotExecTemp=Negaliu �vykdyti byl� laikinajame kataloge. �diegimas nutraukiamas

; *** Startup error messages
LastErrorMessage=%1.%n%nKlaida %2: %3
SetupFileMissing=�diegimo kataloge nerastas failas %1. Pra�ome i�taisyti �i� problem� arba �sigyti nauj� programos kopij�.
SetupFileCorrupt=�diegimo failai sugadinti. �sigykite nauj� programos kopij�.
SetupFileCorruptOrWrongVer=�diegiami failai yra sugadinti arba nesuderinti su �diegimo Programa. I�taisykite problem� arba �sigykite nauj� programos kopij�.
NotOnThisPlatform=�i programa negali b�ti paleista po %1.
OnlyOnThisPlatform=�i programa turi b�ti leid�iama po %1.
WinVersionTooLowError=�i programa reikalauja %1 %2 ar v�lesn�s versijos.
WinVersionTooHighError=�i programa negali b�ti �diegta po %1 %2 ar v�lesne versija.
AdminPrivilegesRequired=�ios programos �diegimui privalote b�ti prisijung�s Administratoriaus teis�mis.
PowerUserPrivilegesRequired=�ios programos �diegimui privalote b�ti prisijung�s Administratoriaus arba Power Users grup�s nario teis�mis.
SetupAppRunningError=�diegimo Programa aptiko, kad yra paleista %1.%n%nU�darykite visas paleistas �ios programos kopijas ir jei norite t�sti paspauskite Gerai arba At�aukti, kad nutraukti �diegim�.
UninstallAppRunningError=Pa�alinimo programa aptiko, kad yra paleista %1.%n%nU�darykite visas paleistas �ios programos kopijas ir jei norite t�sti paspauskite Gerai arba At�aukti, kad nutraukti �diegim�.

; *** Misc. errors
ErrorCreatingDir=�diegimo Programa negali sukurti katalogo "%1"
ErrorTooManyFilesInDir=Ne�manoma sukurti bylos kataloge "%1" nes jame per daug byl�

; *** Setup common messages
ExitSetupTitle=U�daryti �diegimo Program�
ExitSetupMessage=�diegimas nebaigtas. Jei dabar i�eisite, programa nebus �diegta.%n%nJ�s galite paleisti �diegimo Program� kit� kart�, kad pabaigtum�te �diegim�.%n%nU�daryti �diegimo Program�?
AboutSetupMenuItem=&Apie �diegimo Program�...
AboutSetupTitle=Apie �diegimo Program�
AboutSetupMessage=%1 versija %2%n%3%n%n%1 puslapis internete:%n%4
AboutSetupNote=

; *** Buttons
ButtonBack=< &Atgal
ButtonNext=&Pirmyn >
ButtonInstall=�&diegti
ButtonOK=Gerai
ButtonCancel=At�aukti
ButtonYes=&Taip
ButtonYesToAll=Taip &visk�
ButtonNo=&Ne
ButtonNoToAll=N&e nieko
ButtonFinish=&Pabaiga
ButtonBrowse=&Nurodyti...
ButtonWizardBrowse=Nu&rodyti...
ButtonNewFolder=&Naujas katalogas

; *** "Select Language" dialog messages
SelectLanguageTitle=Nurodykite �diegimo Programos kalb�
SelectLanguageLabel=Nurodykite �diegimo metu naudojam� kalb�:

; *** Common wizard text
ClickNext=Paspauskite Pirmyn, jei norite t�sti, arba At�aukti, jei norite i�eiti i� �diegimo Programos.
BeveledLabel=
BrowseDialogTitle=Nurodykite katalog�
BrowseDialogLabel=Pasirinkite katalog� i� s�ra�o ir paspauskite Gerai.
NewFolderName=Naujas katalogas

; *** "Welcome" wizard page
WelcomeLabel1=Sveiki atvyk� � [name] �diegimo Program�
WelcomeLabel2=�diegimo Programa �diegs [name] J�s� kompiuteryje.%n%nPrie� t�siant �diegim�, rekomenduojama u�daryti visas nereikalingas programas.


; *** "Password" wizard page
WizardPassword=Slapta�odis
PasswordLabel1=�is �diegimas yra apsaugotas slapta�od�iu.
PasswordLabel3=�veskite slapta�od� ir spauskite Pirmyn, jei norite t�sti �diegim�. Atkreipkite d�mes�: did�iosios ir ma�osios raid�s vertinamos skirtingai (case sensitive).
PasswordEditLabel=&Slapta�odis:
IncorrectPassword=�vestas slapta�odis yra neteisingas. Pra�ome bandyti i� naujo.

; *** "License Agreement" wizard page
WizardLicense=Licencin� Sutartis
LicenseLabel=Pra�ome perkaityti �i� informacij� prie� t�siant �diegim�.
LicenseLabel3=Pra�ome perskaityti Licencijos Sutart�. Prie� t�sdami �diegim� J�s turite sutikti su reikalavimais.
LicenseAccepted=A� &sutinku su reikalavimais
LicenseNotAccepted=A� &nesutinku su reikalavimais

; *** "Information" wizard pages
WizardInfoBefore=Informacija
InfoBeforeLabel=Pra�ome perskaityti �i� informacij� prie� t�siant �diegim�.
InfoBeforeClickLabel=Kai b�site pasiruo��s t�sti �diegim�, spauskite Pirmyn.
WizardInfoAfter=Informacija
InfoAfterLabel=Pra�ome perskaityti �i� informacij� prie� t�siant �diegim�.
InfoAfterClickLabel=Kai b�site pasiruo��s t�sti �diegim�, spauskite Pirmyn.

; *** "User Information" wizard page
WizardUserInfo=Informacija apie vartotoj�
UserInfoDesc=Pra�ome �vesti vartotojo duomenis.
UserInfoName=&Vartotojo vardas:
UserInfoOrg=&Organizacija:
UserInfoSerial=&Serijinis numeris:
UserInfoNameRequired=J�s privalote �vesti vard�.

; *** "Select Destination Location" wizard page
WizardSelectDir=Pasirinkite �diegimo katalog�
SelectDirDesc=Kur turi b�ti �diegta [name]?
SelectDirLabel3=�diegimo Programa �diegs [name] � nurodyt� katalog�.
SelectDirBrowseLabel=Nor�dami t�sti �diegim� spauskite Pirmyn. Jei norite pasirinkti kit� katalog�, spauskite Nurodyti.
DiskSpaceMBLabel=Reikia ma�iausiai [mb] MB laisvos vietos kietajame diske.
ToUNCPathname=�diegimo Programa negali �diegti � UNC tipo katalog�. Jeigu bandote �diegti program� tinkle, reikia sukurti tinklin� disk� (Map Disk) ir nurodyti reikiam� katalog�.
InvalidPath=J�s privalote para�yti piln� keli� su disko raide; pavyzd�iui:%n%nC:\APP%n% ir negalima nurodyti UNC tipo katalog�:%n%n\\Serveris\share
InvalidDrive=Diskas, kur� nurod�te neegzistuoja arba yra neprieinamas. Pra�ome nurodyti kit� disk� ir/arba katalog�.
DiskSpaceWarningTitle=Nepakanka laisvos vietos diske
DiskSpaceWarning=�diegimas reikalauja bent %1 KB laisvos vietos, bet nurodytame diske yra tik %2 KB laisvos vietos.%n%nAr J�s vis tiek norite t�sti?
DirNameTooLong=Katalogo pavadinimas ar kelias iki jo per ilgas.
InvalidDirName=Nekorekti�kas katalogo pavadinimas.
BadDirName32=Katalogo pavadinime neturi b�ti simboli�:%n%n%1
DirExistsTitle=Toks katalogas egzistuoja
DirExists=Katalogas:%n%n%1%n%n jau egzistuoja. Ar vistiek norite �diegti program� tame kataloge?
DirDoesntExistTitle=Toks katalogas neegzistuoja.
DirDoesntExist=Katalogas:%n%n%1%n%n neegzistuoja. Ar norite kad katalogas b�t� sukurtas?

; *** "Select Components" wizard page
WizardSelectComponents=Komponent� pasirinkimas
SelectComponentsDesc=Kurie komponentai turi b�ti �diegti?
SelectComponentsLabel2=Pa�ym�kite komponentus, kuriuos norite �diegti; nuimkite �ymes nuo komponent�, kuri� nenorite �diegti. Kai b�site pasiruo��s t�sti, spauskite Pirmyn.
FullInstallation=Pilnas vis� komponent� �diegimas
; if possible don't translate 'Compact' as 'Minimal' (I mean 'Minimal' in your language)
CompactInstallation=Glaustas (Compact) �diegimas
CustomInstallation=Pasirinktinis (Custom) �diegimas
NoUninstallWarningTitle=Komponentai egzistuoja
NoUninstallWarning=�diegimo Programa aptiko, kad �ie komponentai jau �diegti J�s� kompiuteryje:%n%n%1%n%nJei nuimsite �ymes nuo �i� komponent�, jie vis tiek nebus i�trinti.%n%nAr vis tiek norite t�sti �diegim�?
ComponentSize1=%1 KB
ComponentSize2=%1 MB
ComponentsDiskSpaceMBLabel=Dabartinis J�s� pasirinkimas reikalauja [mb] MB laisvos vietos diske.

; *** "Select Additional Tasks" wizard page
WizardSelectTasks=Nurodykite papildomas operacijas
SelectTasksDesc=Kokias papildomas operacijas reikia �vykdyti?
SelectTasksLabel2=Nurodykite papildomas operacijas, kurias �diegimo Programa �vykdys, kai bus diegiama [name]. Kai b�site pasiruo��s t�sti �diegim�, spauskite Pirmyn.

; *** "Select Start Menu Folder" wizard page
WizardSelectProgramGroup=Nurodykite Start Menu katalog�
SelectStartMenuFolderDesc=Kur �diegimo Programa tur�t� sukurti nuorodas?
SelectStartMenuFolderLabel3=Nuorodos bus sukurtos �iame Start Menu kataloge.
SelectStartMenuFolderBrowseLabel=Nor�dami t�sti �diegim� spauskite Pirmyn. Jei norite pasirinkti kit� katalog�, spauskite Nurodyti.
NoIconsCheck=&Nekurti joki� nuorod�
MustEnterGroupName=J�s privalote �vesti katalogo pavadinim�.
GroupNameTooLong=Katalogo pavadinimas ar kelias iki jo per ilgas.
InvalidGroupName=Katalogo pavadinimas yra nekorekti�kas
BadGroupName=Katalogo pavadinime neturi b�ti simboli�:%n%n%1
NoProgramGroupCheck2=&Nekurti Start Menu katalogo

; *** "Ready to Install" wizard page
WizardReady=Pasirengta �diegimui
ReadyLabel1=�diegimo Programa pasirengusi �diegti [name] J�s� kompiuteryje.
ReadyLabel2a=Spauskite �diegti, jei norite t�sti �diegim�, arba Atgal, jeigu norite per�i�r�ti nustatymus arba juos pakeisti.
ReadyLabel2b=Spauskite �diegti, jei norite t�sti �diegim�.
ReadyMemoUserInfo=Vartotojo informacija:
ReadyMemoDir=Katalogas �diegimui:
ReadyMemoType=�diegimo tipas:
ReadyMemoComponents=Pasirinkti komponentai:
ReadyMemoGroup=Start Menu katalogas:
ReadyMemoTasks=Papildomos operacijos:

; *** "Preparing to Install" wizard page
WizardPreparing=Pasirengimas �diegimui
PreparingDesc=�diegimo Programa pasirengusi [name] �diegimui J�s� kompiuteryje.
PreviousInstallNotCompleted=Ankstesn�s programos �diegimas/�alinimas buvo neu�baigtas. J�s reik�t� perkrauti kompiuter�, kad u�baigtum�te �diegim�.%n%nKai perkrausite kompiuter�, paleiskite �diegimo Program� dar kart�, kad pabaigtum�te [name] �diegim�.
CannotContinue=�diegimas negali b�ti t�siamas. Pra�ome paspausti At�aukti, kad i�eitum�te i� �diegimo.

; *** "Installing" wizard page
WizardInstalling=�diegimas vyksta
InstallingLabel=Pra�au palaukti kol �diegimo Programa �diegs [name] J�s� kompiuteryje.

; *** "Setup Completed" wizard page
FinishedHeadingLabel=[name] �diegimas baigtas
FinishedLabelNoIcons=�diegimo Programa baig� [name] �diegim� J�s� kompiuteryje.
FinishedLabel=�diegimo Programa baig� [name] �diegim� J�s� kompiuteryje. Programa gali b�ti paleista pasirinkus atitinkamas nuorodas.
ClickFinish=Spauskite Pabaiga, kad u�darytum�te �diegimo Program�.
FinishedRestartLabel=S�kmingam [name] �diegimui, reik�t� perkrauti kompiuter�. Ar norite perkrauti j� dabar?
FinishedRestartMessage=S�kmingam [name] �diegimui, reik�t� perkrauti kompiuter�.%n%nAr norite perkrauti j� dabar?
ShowReadmeCheck=Taip, a� nor��iau perskaityti README byl�
YesRadio=&Taip, a� noriu perkrauti kompiuter� dabar
NoRadio=&Ne, a� perkrausiu kompiuter� v�liau
; used for example as 'Run MyProg.exe'
RunEntryExec=Paleisti %1
; used for example as 'View Readme.txt'
RunEntryShellExec=Per�i�r�ti %1

; *** "Setup Needs the Next Disk" stuff
ChangeDiskTitle=�diegimo Programai reikia kito diskelio
SelectDiskLabel2=Id�kite diskel� %1 ir spauskite Gerai.%n%nJeigu reikiamos bylos gali b�ti surastos kitame kataloge, nei pavaizduota �emiau, �veskite teising� keli� arba spauskite Nurodyti.
PathLabel=&Katalogas:
FileNotInDir2=Byla "%1" nesurasta kataloge "%2". Pra�ome �d�ti teising� diskel� arba nurodyti teising� keli�.
SelectDirectoryLabel=Pra�ome nurodyti kito diskelio viet�.

; *** Installation phase messages
SetupAborted=�diegimas nebuvo baigtas.%n%nPra�ome i�spr�sti problem� ir paleisti �diegimo Program� v�liau.
EntryAbortRetryIgnore=Spauskite Retry jeigu norite bandyti v�l, Ignore - t�sti vistiek, arba Abort, kad nutrauktum�te �diegim�.

; *** Installation status messages
StatusCreateDirs=Kuriami katalogai...
StatusExtractFiles=I�pakuojamos bylos...
StatusCreateIcons=Kuriamos nuorodos...
StatusCreateIniEntries=Kuriami INI �ra�ai...
StatusCreateRegistryEntries=Kuriami registro �ra�ai...
StatusRegisterFiles=Registruojamos bylos...
StatusSavingUninstall=I�saugoma informacija programos pa�alinimui...
StatusRunProgram=Baigiamas �diegimas...
StatusRollback=Anuliuojami pakeitimai...

; *** Misc. errors
ErrorInternal2=Vidin� klaida: %1
ErrorFunctionFailedNoCode=%1 nepavyko
ErrorFunctionFailed=%1 nepavyko; kodas %2
ErrorFunctionFailedWithMessage=%1 nepavyko; kodas %2.%n%3
ErrorExecutingProgram=Nepavyko paleisti bylos:%n%1

; *** Registry errors
ErrorRegOpenKey=Klaida skaitant registro �ra��:%n%1\%2
ErrorRegCreateKey=Klaida sukuriant registro �ra��:%n%1\%2
ErrorRegWriteKey=Klaida ra�ant registro �ra��:%n%1\%2

; *** INI errors
ErrorIniEntry=Klaida ra�ant INI �ra�� byloje "%1".

; *** File copying errors
FileAbortRetryIgnore=Spauskite Retry, kad bandyti dar kart�, Ignore - praleisti fail� (nerekomenduojama), arba Abort - nutraukti �diegim�.
FileAbortRetryIgnore2=Spauskite Retry, kad bandyti dar kart�, Ignore - t�sti vistiek (nerekomenduojama), arba Abort - nutraukti �diegim�.
SourceIsCorrupted=Byla sugadinta
SourceDoesntExist=Byla "%1" neegzistuoja
ExistingFileReadOnly=Egzistuojanti byla yra read-only.%n%nSpauskite Retry i�trinti read-only atribut� ir bandyti v�l, Ignore praleisti fail�, arba Abort nutraukti �diegim�.
ErrorReadingExistingDest=Klaida �vyko skaitant byl�:
FileExists=Tokia byla jau egzistuoja.%n%nAr norite, kad �diegimo Programa perra�yt� byl�?
ExistingFileNewer=Egzistuojanti byla yra naujesn� u� t�, kuri� �diegimo Programa bando �ra�yti. Rekomenduojama palikti esan�i� naujesn� byl�.%n%nAr norite palikti naujesn� byl�?
ErrorChangingAttr=Klaida �vyko kei�iant bylos atributus:
ErrorCreatingTemp=Klaida �vyko kuriant byl� pasirinktame kataloge:
ErrorReadingSource=Klaida �vyko skaitant diegiam�j� byl�:
ErrorCopying=Klaida �vyko kopijuojant byl�:
ErrorReplacingExistingFile=Klaida �vyko perra�ant egzistuojan�i� byl�:
ErrorRestartReplace=Perkrovimas/Perra�ymas nepavyko:
ErrorRenamingTemp=Klaida �vyko pervadinant byl� pasirinktame kataloge:
ErrorRegisterServer=Nepavyko u�registruoti DLL/OCX bibliotekos: %1
ErrorRegisterServerMissingExport=DllRegisterServer eksport funkcija nerasta
ErrorRegisterTypeLib=Nepavyko u�registruoti tip� bibliotekos: %1

; *** Post-installation errors
ErrorOpeningReadme=Klaida �vyko bandant atidaryti README byl�.
ErrorRestartingComputer=�diegimo Programa negali perkrauti kompiuterio. Pra�ome perkrauti kompiuter� �prastu b�du.

; *** Uninstaller messages
UninstallNotFound=Byla "%1" neegzistuoja. Pa�alinti ne�manoma.
UninstallOpenError=Byla "%1" negali b�ti atidaryta. Pa�alinti ne�manoma.
UninstallUnsupportedVer=Pa�alinimo log byla "%1" yra formate, kurio nesupranta pa�alinimo programa. Pa�alinti ne�manoma.
UninstallUnknownEntry=Ne�inomas �ra�as (%1) rastas pa�alinimo log byloje
ConfirmUninstall=Ar esate tikras, kad norite pa�alinti %1 ir visus priklausan�ius komponentus?
OnlyAdminCanUninstall=Tik administratoriaus teises turintis vartotojas gali pa�alinti program�.
UninstallStatusLabel=Pra�ome palaukti, kol %1 bus pa�alinta i� J�s� kompiuterio.
UninstalledAll=%1 buvo s�kmingai pa�alinta i� J�s� kompiuterio.
UninstalledMost=%1 pa�alinimas s�kmingai baigtas.%n%nKai kurie elementai nebuvo i�trinti - juos galite pa�alinti rankiniu b�du.
UninstalledAndNeedsRestart=Kad baigti %1 pa�alinim�, J�s� kompiuteris turi b�ti perkrautas.%n%nAr norite perkrauti j� dabar?
UninstallDataCorrupted="%1" byla yra sugadinta. Programos pa�alinti ne�manoma.

; *** Uninstallation phase messages
ConfirmDeleteSharedFileTitle=I�trinti bendras (shared) bylas?
ConfirmDeleteSharedFile2=Aptikta, kad jokia programa nenaudoja bendr� byl�. Ar norite i�trinti bendras bylas? %n%nJeigu kurios nors programos naudoja �ias bylas ir jos bus i�trintos, tos programos gali veikti neteisingai. Jeigu nesate tikras - spauskite Ne. Bylos palikimas J�s� kompiuteryje nesukels joki� problem�.
SharedFileNameLabel=Bylos pavadinimas:
SharedFileLocationLabel=Vieta:
WizardUninstalling=Pa�alinimo b�sena
StatusUninstalling=�alinama %1...

; The custom messages below aren't used by Setup itself, but if you make
; use of them in your scripts, you'll want to translate them.

[CustomMessages]

NameAndVersion=%1 versija %2
AdditionalIcons=Papildomos piktogramos:
CreateDesktopIcon=Sukurti piktogram� &Darbalaukyje
CreateQuickLaunchIcon=Sukurti Spar�iosios &Paleisties piktogram�
ProgramOnTheWeb=%1 �iniatinklyje
UninstallProgram=Pa�alinti %1
LaunchProgram=Paleisti %1
AssocFileExtension=&Susieti %1 program� su bylos pl�tiniu %2
AssocingFileExtension=%1 programa susiejama su bylos pl�tiniu %2...