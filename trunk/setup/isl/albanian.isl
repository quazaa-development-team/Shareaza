; *** Inno Setup version 5.1.0+ Albanian messages *** - translated by Flakron Bytyqi 
; email : flakron_19@yahoo.com
;
; To download user-contributed translations of this file, go to:
;   http://www.jrsoftware.org/is3rdparty.php
;
; Note: When translating this text, do not add periods (.) to the end of
; messages that didn't have them already, because on those messages Inno
; Setup adds the periods automatically (appending a period would result in
; two periods being displayed).

[LangOptions]
; The following three entries are very important. Be sure to read and 
; understand the '[LangOptions] section' topic in the help file.
LanguageName=Albanian
LanguageID=$041c
LanguageCodePage=0
; If the language you are translating to requires special font faces or
; sizes, uncomment any of the following entries and change them accordingly.
;DialogFontName=
;DialogFontSize=8
;WelcomeFontName=Verdana
;WelcomeFontSize=12
;TitleFontName=Arial
;TitleFontSize=29
;CopyrightFontName=Arial
;CopyrightFontSize=8

[Messages]

; *** Application titles
SetupAppTitle=Instalimi
SetupWindowTitle=Instalimi i - %1
UninstallAppTitle=Uninstalimi
UninstallAppFullTitle=Uninstalimi i %1

; *** Misc. common
InformationTitle=Informacion
ConfirmTitle=Konfirmo
ErrorTitle=Gabim

; *** SetupLdr messages
SetupLdrStartupMessage=Kjo do t� instaloj %1. A d�shiron t� vazhdosh?
LdrCannotCreateTemp=Nuk mund t� krijohej nj� fajll i p�rkohsh�m. Instalimi u ndal
LdrCannotExecTemp=Nuk mund t� ekzekutohej nj� fajll n� direktoriumin e p�rkohshem. Instalimi u ndal

; *** Startup error messages
LastErrorMessage=%1.%n%nGabim %2: %3
SetupFileMissing=Fajlli %1 po mungon prej direktoriumit instalues. Ju lutem rregollone problemin ose merrni nj� kopje t� re t� programit.
SetupFileCorrupt=Fajllat instalues jan� t� korruptuar. Ju lutem merrni nj� kopje t� re t� programit.
SetupFileCorruptOrWrongVer=Fajllat instalues jan� t� korruptuar, ose jan� inkompaktibil me k�t� verzion t� instaluesit. Ju lutem rregullone problemin ose merrni nj� kopje t� re t� programit.
NotOnThisPlatform=Ky program nuk do t� punoj n� %1.
OnlyOnThisPlatform=Ky program duhet t� punoj n�  %1.
OnlyOnTheseArchitectures=Ky program mund t� instalohet vet�m n� verzionet e Windows t� dizajnuara p�r k�t� arkitektur� t� procesor�ve:%n%n%1
MissingWOW64APIs=Ky verzion i Windows q� po e p�rdorni nuk i kryen funksionet q� i k�rkon Instalimi p�r t� b�r� Instalim 64-bit�sh. P�r ta rregulluar k�t� problem, ju lutem instalone Service Pack %1.
WinVersionTooLowError=K�ti programi i nevojitet %1 verzioni %2 ose m�tej.
WinVersionTooHighError=Ky program nuk mund t� instalohet n� %1 verzioni %2 ose m�tej.
AdminPrivilegesRequired=Ju duhet t� jeni Administrator q� ta instaloni k�t� program.
PowerUserPrivilegesRequired=Ju duhet t� jeni Administrator ose Power User p�r ta instaluar k�t� program.
SetupAppRunningError=Instalimi ka detektuar q� %1 momentalisht �sht� duke punuar.%n%nJu lutem ndalni t� gjitha pun�t, pastaj klikoni Mir� q� t� vazhdoni, ose Anulo q� ta ndalni Instalimin.
UninstallAppRunningError=Instalimi ka detektuar q� %1 momentalisht �sht� duke punuar.%n%nJu lutem ndalni t� gjitha pun�t, pastaj klikoni Mir� q� t� vazhdoni, ose Anulo q� ta ndalni Instalimin.

; *** Misc. errors
ErrorCreatingDir=Instalimi nuk mundi t� krijoi direktoriumin "%1"
ErrorTooManyFilesInDir=E pamundur t� krijohet fajlli n� direktoriumin "%1" sepse ka shum� fajlla n� t�

; *** Setup common messages
ExitSetupTitle=Ndale Instalimin
ExitSetupMessage=Instalimi nuk �sht� kompletuar. N� qoft� se e ndalni tani, programi nuk do t� instalohet.%n%nJu mundeni tjera her� ta l�shoni instalimin q� ta p�rfundoni instalimin.%n%nT� ndalet Instalimi?
AboutSetupMenuItem=&P�r Instalimin...
AboutSetupTitle=P�r Instalimin
AboutSetupMessage=%1 verzioni %2%n%3%n%n%1 web faqja:%n%4
AboutSetupNote=
TranslatorNote= Translated from Flakron Bytyqi (flakron_19@yahoo.com)

; *** Buttons
ButtonBack=< &Prapa
ButtonNext=&Vazhdo >
ButtonInstall=&Instalo
ButtonOK=Mir�
ButtonCancel=Anulo
ButtonYes=&Po
ButtonYesToAll=PO t� &gjithave
ButtonNo=&Jo
ButtonNoToAll=J&O t� gjithave
ButtonFinish=&P�rfundo
ButtonBrowse=&Lokalizo...
ButtonWizardBrowse=L&okalizo...
ButtonNewFolder=&Krijo follder t� ri

; *** "Select Language" dialog messages
SelectLanguageTitle=Zgjedhe gjuh�n e instalimit
SelectLanguageLabel=Zgjedhe gjuh�n q� do t� p�rdoret gjat� instalimit:

; *** Common wizard text
ClickNext=Kliko Vazhdo p�r t� vazhduar, ose Anulo p�r ta ndalur Instalimin.
BeveledLabel=
BrowseDialogTitle=Lokalizo p�r follderin
BrowseDialogLabel=Zgjedhe follderin n� k�t� list�, pastaj kliko Mir�.
NewFolderName=Follderi i ri

; *** "Welcome" wizard page
WelcomeLabel1=Mir� se vini n� Magjistarin e Instalimit t� [name]
WelcomeLabel2=Kjo do t� instaloj [name/ver] n� kompjuterin t�nd.%n%n�sht� e rekomanduar q� t'i mbyllni t� gjtiha programet para se t� vazhdoni.

; *** "Password" wizard page
WizardPassword=Fjal�kalimi
PasswordLabel1=Ky Instalim �sht� i mbrojtur me Fjal�kalim.
PasswordLabel3=Ju lutem shkruane fjal�kalimin, pastaj klikoni Vazhdo p�r t� vazhduar. Fjal�kalimet jan� t� ndijshme ndaj madh�sis� s� shkronjave (p.sh. A dhe a).
PasswordEditLabel=&Fjal�kalimi:
IncorrectPassword=Fjal�kalimin q� e dhat� nuk �sht� korrekt. Ju lutem provoni p�rs�ri.

; *** "License Agreement" wizard page
WizardLicense=Li�enca
LicenseLabel=Ju lutem lexoni k�to informacione t� r�nd�sishme para se t� vazhdoni.
LicenseLabel3=Ju lutem lexone k�t� Li�enc�. Ju duhet t� pajtoheni me kushtet e Li�enc�s para se t� vazhdoni me instalimin.
LicenseAccepted=Un� e &pranoj Li�enc�n
LicenseNotAccepted=Un� &nuk e pranoj Li�enc�n

; *** "Information" wizard pages
WizardInfoBefore=Informacion
InfoBeforeLabel=Ju lutem lexoni k�to informacione t� r�nd�sishme para se t� vazhdoni.
InfoBeforeClickLabel=Kur t� jeni t� gatsh�m me Instalimin, kliko Vazhdo.
WizardInfoAfter=Informacion
InfoAfterLabel=Ju lutem lexoni k�to informacione t� r�nd�sishme para se t� vazhdoni.
InfoAfterClickLabel=Kur t� jeni t� gatsh�m me Instalimin, kliko Vazhdo.

; *** "User Information" wizard page
WizardUserInfo=Informacionet e p�rdoruesit
UserInfoDesc=Ju lutem shkruani informacionet tuaja.
UserInfoName=&Emri i p�rdoruesit:
UserInfoOrg=&Organizata:
UserInfoSerial=&Numri serial:
UserInfoNameRequired=Ju duhet t� shkruani nj� em�r.

; *** "Select Destination Location" wizard page
WizardSelectDir=Zgjedhe destinacionin
SelectDirDesc=Ku duhet [name] t� instalohet?
SelectDirLabel3=Instalimi do t� instaloj [name] n� k�t� follder.
SelectDirBrowseLabel=Q� t� vazhdosh, kliko Vazhdo. N�se d�shiron t� zgjedh�sh nj� follder tjet�r, kliko Lokalizo.
DiskSpaceMBLabel=S� paku [mb] MB t� lir� t� diskut nevojiten.
ToUNCPathname=Instalimi nuk mund t� instaloj n� nj� UNC shteg. N�se jeni duke u munduar q� t� instaloni n� nj� rrjet�, juve ju duhet nj� hart� e diskut t� rrjet�s.
InvalidPath=Ju duhet ta shkruani t�r� shtegun me shkronj�n e diskut; p.sh:%n%nC:\APP%n%nose nj� UNC shteg n� form�n:%n%n\\server\share
InvalidDrive=Disku ose UNC e ndar� e zgjedhur nga ju, nuk ekziston ose nuk �sht� e arritshme. Ju lutem zgjedheni nj� tjet�r.
DiskSpaceWarningTitle=Nuk ka mjaft hap�sir� n� disk
DiskSpaceWarning=Instalimit i duhen s� paku %1 KB t� hap�sir�s s� lir� q� t� instaloj, por disku i zgjedhur ka vet�m %2 KB n� dispozicion.%n%nA d�shironi t� vazhdoni edhe ashtu?
DirNameTooLong=Emri i follderit ose shtegut �sht� shum� i gjat�.
InvalidDirName=Emri i follderit nuk �sht� valid.
BadDirName32=Emri i follderit nuk mund t� ket� asnj�r�n nga k�to karaktere:%n%n%1
DirExistsTitle=Follderi ekziston
DirExists=Follderi:%n%n%1%n%ntanim� ekziston. A d�shironi edhe ashtu t� instaloni n� at� follder?
DirDoesntExistTitle=Follderi nuk ekziston
DirDoesntExist=Follderi:%n%n%1%n%nnuk ekziston. A d�shironi q� follderi t� krijohet?

; *** "Select Components" wizard page
WizardSelectComponents=Zgjedhi komponentet
SelectComponentsDesc=Cilat komponente duhet t� instalohen?
SelectComponentsLabel2=Zgjedhi komponentet q� d�shironi t� instalohen; pastroj komponentet q� nuk d�shironi t� instalohen. Kliko Vazhdo kur t� jeni gati t� vazhdoni.
FullInstallation=Instalimi i plot�
; if possible don't translate 'Compact' as 'Minimal' (I mean 'Minimal' in your language)
CompactInstallation=Instalimi kompakt
CustomInstallation=Instalimi profesional
NoUninstallWarningTitle=Komponenta ekziston
NoUninstallWarning=Instalimi ka detektuar q� k�ta komponenta tashm� jan� t� instaluar n� kompjuterin tuaj:%n%n%1%n%nMoszgjedhja e tyre nuk do t'i uninstaloj ato.%n%nA d�shironi edhe ashtu t� vazhdoni?
ComponentSize1=%1 KB
ComponentSize2=%1 MB
ComponentsDiskSpaceMBLabel=Zgjedhjes aktuale i nevojiten se paku [mb] MB t� hap�sir�s s� lir� t� diskut.

; *** "Select Additional Tasks" wizard page
WizardSelectTasks=Zgjedhi pun�t shtes�
SelectTasksDesc=Cilat pun�t shtes� duhet t� b�hen?
SelectTasksLabel2=Zgjedhi pun�t t� cilat d�shiron q� Instalimi t'i b�j� gjat� instalimit t� [name], pastaj kliko Vazhdo.

; *** "Select Start Menu Folder" wizard page
WizardSelectProgramGroup=Zgjedhe follderin e menus Start
SelectStartMenuFolderDesc=Ku duhet Instalimi t'i vendos shkurtesat e programit?
SelectStartMenuFolderLabel3=Instalimi do t'i vendos shkrutesat n� follderin vijues t� menus Start.
SelectStartMenuFolderBrowseLabel=Q� t� vazhdosh, kliko Vazhdo. N�se d�shiron t� zgjedh�sh nj� follder tjet�r, kliko Lokalizo.
MustEnterGroupName=Ju duhet ta shkruani emrin e follderit.
GroupNameTooLong=Shtegu ose emri i follderit �sht� shum� i gjat�.
InvalidGroupName=Emri i follderit nuk �sht� valid.
BadGroupName=Emri i follderit nuk mund t'i ket� karakteret vijuese:%n%n%1
NoProgramGroupCheck2=&Mos krijo follder n� menun Start

; *** "Ready to Install" wizard page
WizardReady=I gatsh�m p�r t� instaluar
ReadyLabel1=Instalimi �sht� i gatsh�m q� ta instaloj [name] n� komjuterin tuaj.
ReadyLabel2a=Kliko Instalo q� t� vazhdosh me instalimin, ose kliko Prapa n�se d�shiron t'i ndryshosh vendimet tuaja.
ReadyLabel2b=Kliko Instalo q� t� vazhdosh me instalimin.
ReadyMemoUserInfo=Informacione t� p�rdoruesit:
ReadyMemoDir=Destinacioni:
ReadyMemoType=Lloji i instalimit:
ReadyMemoComponents=Zgjedhi komponentet:
ReadyMemoGroup=Follderi i menus Start:
ReadyMemoTasks=Pun�t shtes�:

; *** "Preparing to Install" wizard page
WizardPreparing=Duke u pregaditur p�r t� instaluar
PreparingDesc=Instalimi �sht� duke u pregaditur q� t� instaloj [name] n� kompjuterin tuaj.
PreviousInstallNotCompleted=Instalimi/Uninstalimi i nj� programi nuk �sht� mbaruar. Ju duhet ta ristartoni kompjuterin tuaj q� t� p�rfundohet ai instalim.%n%nPas ristartimit t� kompjuterit tuaj, l�shone Instalimin q� t� kompletohet instalimi i [name].
CannotContinue=Instalimi nuk mund t� vazhdoj. Ju lutem klikoni Anulo q� t� dilni nga programi.

; *** "Installing" wizard page
WizardInstalling=Duke instaluar
InstallingLabel=ju lutem pritni derisa Instalimi ta instaloj [name] n� kompjuterin tuaj.

; *** "Setup Completed" wizard page
FinishedHeadingLabel=Duke kompletuar [name] Magjistarin Instalimi
FinishedLabelNoIcons=Instalimi ka p�rfunduar instalimin e [name] n� kompjuterin tuaj.
FinishedLabel=Instalimi ka p�rfunduar instalimin e [name] n� kompjuterin tuaj. Aplikacioni mund t� l�shohet duke i zgjedhur ikonat e instaluar.
ClickFinish=Kliko P�rfundo q� t� dal�sh nga Instalimi.
FinishedRestartLabel=Q� t� p�rfundoj instalimi i [name], Instalimi duhet ta ristartoj kompjuterin tuaj. A d�shironi ta ristartorni kompjuterin tani?
FinishedRestartMessage=Q� t� kompletohet instalimi i [name], Instalimi duhet ta ristartoj kompjuterin tuaj.%n%nA d�shironi ta ristartoni kompjuterin tani?
ShowReadmeCheck=Po, dua ta shoh fajllin M� LEXO
YesRadio=&Po, ristartoje kompjuterin tani
NoRadio=&Jo, do ta ristartoj kompjuterin m� von�
; used for example as 'Run MyProg.exe'
RunEntryExec=L�sho %1
; used for example as 'View Readme.txt'
RunEntryShellExec=Shiko %1

; *** "Setup Needs the Next Disk" stuff
ChangeDiskTitle=Instalimit i duhet disku tjet�r
SelectDiskLabel2=Ju lutem futeni diskun %1 dhe klikoni Mir�.%n%nN�se fajllat n� k�t� disk mund t� gjenden n� nj� follder tjet�r q� nuk �sht� paraqitur k�tu, shkruane shtegun ose klikoni Lokalizo.
PathLabel=&Shtegu:
FileNotInDir2=Fajlli "%1" nuk �sht� gjetur n� "%2". Ju lutem futeni diskun e duhur ose zgjedhne nj� follder tjet�r.
SelectDirectoryLabel=Ju lutem specifikone lokaconin e diskut tjet�r.

; *** Installation phase messages
SetupAborted=Instalimi nuk �sht� p�rfunduar.%n%nJu lutem rregullone problemin dhe l�shone Instalimin p�rs�ri.
EntryAbortRetryIgnore=Kliko Riprovo q� t� provosh p�rs�ri, Injoro q� t� vazhdosh edhe ashtu, ose Nd�rpreje q� ta ndal�sh instalimin.

; *** Installation status messages
StatusCreateDirs=Duke i krujuar direktoriumet...
StatusExtractFiles=Duke i ekstraktuar fajllat...
StatusCreateIcons=Duke i krijuar shkrutesat...
StatusCreateIniEntries=Duke i krijuar hyrjet INI...
StatusCreateRegistryEntries=Duke i krjuar hyrjet e regjistrit...
StatusRegisterFiles=Duke i regjistruar fajllat...
StatusSavingUninstall=Duke ruajtur informacione t� uninstalimit...
StatusRunProgram=Duke e p�rfunduar instalimin...
StatusRollback=Duke e rikthyer gjendjen para instalimit...

; *** Misc. errors
ErrorInternal2=Gabim i brendsh�m: %1
ErrorFunctionFailedNoCode=%1 d�shtoi
ErrorFunctionFailed=%1 d�shtoi; kodi %2
ErrorFunctionFailedWithMessage=%1 d�shtoi; kodi %2.%n%3
ErrorExecutingProgram=Nuk mund t� ekzekutohej fajlli:%n%1

; *** Registry errors
ErrorRegOpenKey=Gabim gjat� hapjes s� qel�sit t� regjistrit:%n%1\%2
ErrorRegCreateKey=Gabim gjat� krijimit t� qel�sit t� regjistrit:%n%1\%2
ErrorRegWriteKey=Gabim gjat� shkruarjes s� qel�sit t� regjistrit:%n%1\%2

; *** INI errors
ErrorIniEntry=Gabim duke krijuar hyrje INI n� fajllin "%1".

; *** File copying errors
FileAbortRetryIgnore=Kliko Riprovo q� t� provosh p�rs�ri, Injoro q� t� kalosh k�t� fajll (nuk �sht� e rekomanduar), ose Nd�rpreje q� ta ndal�sh instalimin.
FileAbortRetryIgnore2=Kliko Riprovo q� t� provosh p�rs�ri, Injoro q� t� vazhdosh edhe ashtu (nuk �sht� e rekomanduar), ose Nd�rpreje q� ta ndal�sh instalimin.
SourceIsCorrupted=Fajlli burimor �sht� i korruptuar
SourceDoesntExist=Fajlli burimor "%1" nuk ekziston
ExistingFileReadOnly=Fajlli ekzistues �sht� i sh�nuar si read-only.%n%nKliko Riprovo q� ta largosh atributin read-only dhe t� provosh p�rs�ri, Injoro q� ta kalosh k�t� fajll, ose Nd�rpreje q� ta ndal�sh instalimin.
ErrorReadingExistingDest=Nj� gabim ndodhi gjat� leximit t� fajllit ekzistues:
FileExists=Fajlli tashm� ekziston.%n%nA d�shiron q� Instalimi ta mbishkruaj?
ExistingFileNewer=Fajlli ekzistues �sht� m� i ri sesa ai q� d�shiron Instalimi ta instaloj. �sht� e rekomanduar q� ta mbani fajllin ekzistues.%n%nA d�shironi q� ta mbani fajllin ekzistues?
ErrorChangingAttr=Nj� gabim ndodhi gjat� ndrrimit t� atributeve t� fajllit ekzistues:
ErrorCreatingTemp=Nj� gabim ndodhi gajt� krijimit t� nj� fajlli n� direktoriumin destinues:
ErrorReadingSource=Nj� gabim ndodhi gjat� leximit t� fajllit burimor:
ErrorCopying=Nj� gabim ndodhi gjat� kopjimit t� nj� fajlli:
ErrorReplacingExistingFile=Nj� gabim ndodhi gjat� z�vend�simit t� fajllit ekzistues:
ErrorRestartReplace=RistartoZ�vend�so d�shtoi:
ErrorRenamingTemp=Nj� gabim ndodhi gjat� nd�rrimit t� emrit t� nj� fajlli n� direktoriumin destinues:
ErrorRegisterServer=Nuk mund t� regjistrohej DLL/OCX: %1
ErrorRegisterServerMissingExport=DllRegisterServer eksportimi nuk u gjet
ErrorRegisterTypeLib=Nuk mund t� regjistrohej libraria: %1

; *** Post-installation errors
ErrorOpeningReadme=Nj� gabim ndodhi gajt� hapjes s� fajllit M�LEXO.
ErrorRestartingComputer=Instalimi nuk mundi ta ristartoj kompjuterin. Ju lutem b�ne k�t� manualisht.

; *** Uninstaller messages
UninstallNotFound=Fajlli "%1" nuk ekziston. Nuk mund t� uninstaloj.
UninstallOpenError=Fajlli "%1" nuk mund t� hapej. Nuk mund t� uninstaloj
UninstallUnsupportedVer=Fajlli log i uninstalimit "%1" �sht� n� format q� nuk e njeh ky verzion i uninstalimit. Nuk mund t� uninstaloj
UninstallUnknownEntry=Nj� hyrje e panjohur (%1) �sht� gjetur n� log t� uninstalimit
ConfirmUninstall=A jeni i sigurt q� d�shironi kompletisht ta largoni %1 dhe t� gjitha komponentet e tij?
UninstallOnlyOnWin64=Ky instalim mundet vet�m t� uninstalohet n� verzionet 64 bit t� Windows.
OnlyAdminCanUninstall=Ky instalim mund t� uninstalohet vet�m nga p�rdoruesit me privilegje t� administruese.
UninstallStatusLabel=Ju lutem prtini deri sa %1 t� largohet nga kompjuteri juaj.
UninstalledAll=%1 �sht� larguar me sukses nga kompjuteri juaj.
UninstalledMost=%1 uninstalimi u kompletua.%n%nDisa elemente nuk mund t� largohen. Ato mund t� largohen manualisht.
UninstalledAndNeedsRestart=Q� t� kompletohet uninstalimi i %1, kompjuteri juaj duhet t� ristartohet.%n%nA d�shironi ta ristartoni tani?
UninstallDataCorrupted="%1" fajlli �sht� korruptuar. Nuk mund t� uninstaloj

; *** Uninstallation phase messages
ConfirmDeleteSharedFileTitle=A t� largohet Fajlli i Ndar�?
ConfirmDeleteSharedFile2=Sistemi tregon q� fajlli i ndar� nuk �sht� n� p�rdorim nga asnj� program. A d�shironi q� Uninstalimi ta largoj k�t� Fajll t� Ndar�?%n%nN�se ka programe q� e p�rdorin dhe fajlli largohet, programet nuk do t� funksionojn si duhet. N�se nuk jeni i sigurt, kliko Jo. Q� ta leni fajllin n� sistemin tuaj nuk do ta d�mtoj sistemin.
SharedFileNameLabel=Emri i fajllit:
SharedFileLocationLabel=Vendi:
WizardUninstalling=Statusi i uninstalimit
StatusUninstalling=Duke uninstaluar %1...

; The custom messages below aren't used by Setup itself, but if you make
; use of them in your scripts, you'll want to translate them.

[CustomMessages]

NameAndVersion=%1 verzioni %2
AdditionalIcons=Ikonat shtes�:
CreateDesktopIcon=Krijo nj� &ikon n� dektop
CreateQuickLaunchIcon=Krijo nj� ikon n� &Quick Launch
ProgramOnTheWeb=%1 n� internet
UninstallProgram=Uninstalo %1
LaunchProgram=L�sho %1
AssocFileExtension=&Lidhe %1 me %2 ekstensionet e fajllave
AssocingFileExtension=Duke e lidhur %1 me %2 ekstensionet e fajllave...
