; *** Inno Setup version 4.2.2+ Spanish Messages ***
;
; To download user-contributed translations of this file, go to:
;   http://www.jrsoftware.org/is3rdparty.php
;
; Hecho por: Luis Carlos Colunga (Help)
; Para: Shareaza Installation
; Made by: Luis Carlos Colunga (Help
; For: Shareaza Installation
;
; $jrsoftware: issrc/Files/Default.isl,v 1.58 2004/04/07 20:17:13 jr Exp $

[LangOptions]
LanguageName=Espa<00F1>ol
LanguageID=$1034
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
SetupAppTitle=Instalaci�n
SetupWindowTitle=Instalaci�n - %1
UninstallAppTitle=Desinstalar
UninstallAppFullTitle=Desinstalar %1

; *** Misc. common
InformationTitle=Informaci�n
ConfirmTitle=Confirmar
ErrorTitle=Error

; *** SetupLdr messages
SetupLdrStartupMessage=Esto va instalar %1. �Deseas continuar?
LdrCannotCreateTemp=No s� pudo crear el archivo temporal. Instalaci�n Abortada
LdrCannotExecTemp=No s� pudo ejecutar el archivo de la carpeta temporal. Instalaci�n Abortada

; *** Startup error messages
LastErrorMessage=%1.%n%nError %2: %3
SetupFileMissing=El archivo %1 no est� en la carpeta del Instalador. Por favor corrige o consigue una nueva copia del programa.
SetupFileCorrupt=Los archivos del Instalador son corruptos. Por favor consigue una nueva copia del programa.
SetupFileCorruptOrWrongVer=Los archivos del Instalador son corruptos, o son incompatibles con esta versi�n del Instalador. Por favor corrige o consigue una nueva copia del programa.
NotOnThisPlatform=Este programa no va a correr en %1.
OnlyOnThisPlatform=Este programa debe ser corrido en %1.
WinVersionTooLowError=Este programa requiere la versi�n %1 %2 o m�s nueva.
WinVersionTooHighError=Este programa no puede ser instalado en la %1 versi�n %2 o m�s nueva.
AdminPrivilegesRequired=Debes de estar logeado como administrador para instalar este programa.
PowerUserPrivilegesRequired=Usted debe estar logeado como Administrador o Power Member al instalar este programa.
SetupAppRunningError=El Instalador ha detectado que %1 esta siendo ejecutado.%n%nPor favor cierralo, y despu�s haz click a OK para continuar, o Cancelar para salir.
UninstallAppRunningError=La desinstalaci�n ha detectado que %1 esta corriendo.%n%nPor favor ci�rralo, y despu�s haz click a OK para continuar, o Cancelar para salir.

; *** Misc. errors
ErrorCreatingDir=El Instalador no pudo crear la carpeta "%1"
ErrorTooManyFilesInDir=No se pudo crear la carpeta "%1" porque contiene muchos archivos

; *** Setup common messages
ExitSetupTitle=Salir del Instalador
ExitSetupMessage=La instalaci�n no esta completa. Si lo quitas ahora, el programa no va a ser instalado.%n%nPuedes volver a correr el instalador otra vez en otro tiempo para completar la instalaci�n.%n%n�Salir de la instalaci�n?
AboutSetupMenuItem=&About Setup...
AboutSetupTitle=About Setup
AboutSetupMessage=%1 version %2%n%3%n%n%1 home page:%n%4
AboutSetupNote=

; *** Buttons
ButtonBack=< &Atr�s
ButtonNext=&Siguiente >
ButtonInstall=&Instalar
ButtonOK=OK
ButtonCancel=Cancelar
ButtonYes=&Si
ButtonYesToAll=Si &a todo
ButtonNo=&No
ButtonNoToAll=N&o a todo
ButtonFinish=Terminar
ButtonBrowse=&Explorar..
ButtonWizardBrowse=E&plorar...
ButtonNewFolder=&Hacer nueva carpeta

; *** "Select Language" dialog messages
SelectLanguageTitle=Seleccionar lenguaje de instalaci�n
SelectLanguageLabel=Seleccione el lenguaje que desea usar durante la instalaci�n:

; *** Common wizard text
ClickNext=Oprima Siguiente para continuar, o Cancelar para salir de la instalaci�n.
BeveledLabel=
BrowseDialogTitle=Explorar Carpeta
BrowseDialogLabel=Selecciona una carpeta de la lista siguiente, despu�s haz click a OK.
NewFolderName=Nueva Carpeta

; *** "Welcome" wizard page
WelcomeLabel1=Bienvenido al asistente de instalaci�n de [name]
WelcomeLabel2=Este proceso instalar� [name/ver] en su computadora.%n%nSe recomienda que cierre el resto de las aplicaciones antes de continuar.

; *** "Password" wizard page
WizardPassword=Contrase�a
PasswordLabel1=Esta instalaci�n est� protegida con contrase�a.
PasswordLabel3=PasswordLabel3=Por favor escriba su contrase�a y despu�s haga click al bot�n Siguiente para continuar.  Las contrase�as son sensitivas a las may�sculas.
PasswordEditLabel=&Contrase�a:
IncorrectPassword=La contrase�a es incorrecta.  Intente de nuevo.

; *** "License Agreement" wizard page
WizardLicense=Acuerdo de licencia
LicenseLabel=Lea cuidadosamente la siguiente informaci�n antes de continuar.
LicenseLabel3=Lea el siguiente acuerdo de licencia.  Deber� aceptar los t�rminos de este acuerdo antes de continuar con la instalaci�n.
LicenseAccepted=&Acepto el acuerdo
LicenseNotAccepted=No acepto el acuer&do

; *** "Information" wizard pages
WizardInfoBefore=Informaci�n
InfoBeforeLabel=Lea la siguiente informaci�n antes de continuar.
InfoBeforeClickLabel=Cuando est� listo para continuar la Instalaci�n, haga click a Siguiente.
WizardInfoAfter=Informac�on
InfoAfterLabel=Cuando est� listo para continuar la instalaci�n, haga click al bot�n Siguiente.
InfoAfterClickLabel=Cuando est� listo para continuar la instalaci�n, haga click al bot�n Siguiente.

; *** "User Information" wizard page
WizardUserInfo=Informaci�n del usuario
UserInfoDesc=Favor de teclear su informaci�n.
UserInfoName=Nombre del &usuario:
UserInfoOrg=&Organizaci�n:
UserInfoSerial=N�mero de &serie:
UserInfoNameRequired=Debe dar un nombre.

; *** "Select Destination Location" wizard page
WizardSelectDir= *** P�gina de "Selecci�n de carpeta destino" del asistente
SelectDirDesc=�Donde desea instalar [name]?
SelectDirLabel3=El Instalador va a instalar [name] en la siguiente carpeta
SelectDirBrowseLabel=Para continuar, haga click a Siguiente. Si deseas instalar el programa en otra carpeta, haga click a Explorar.
DiskSpaceMBLabel=Por lo menos [mb] MB de espacio libre en su disco duro es requerido.
ToUNCPathname=El Instalador no puede instalar a un destino UNC. Si estas tratando de instalar a una red, debes de mapear la letra de la unidad de la red.
InvalidPath=Debes dar un destino completo con una letra de unidad; por ejemplo:%n%nC:\APP%n%no un destino UNC como:%n%n\\server\share
InvalidDrive=La unidad o un UNC que seleccionaste no existe o no es accesible. Por favor selecciona otro.
DiskSpaceWarningTitle=No hay suficiente espacio en el disco duro
DiskSpaceWarning=El Instalador requiere por lo menos %1 KB de espacio libre para instalar, pero la unidad seleccionada solo contiene %2 KB disponible.%n%nDeseas continuar?
DirNameTooLong=El nombre de la carpeta o el destino es muy largo.
InvalidDirName=El nombre de la carpeta no es valido.
BadDirName32=Los nombres de la carpeta no pueden incluir alguno de estos caracteres:%n%n%1
DirExistsTitle=La Carpeta Existe
DirExists=La Carpeta:%n%n%1%n%nya existe. �Desear�a instalarlo en es carpeta de todas maneras?
DirDoesntExistTitle=Folder Does Not Exist
DirDoesntExist=The folder:%n%n%1%n%ndoes not exist. �Desear�as que la carpeta sea creada?

; *** "Select Components" wizard page
WizardSelectComponents=Seleccionar Componentes
SelectComponentsDesc=Cuales componentes deseas que sean instalados?
SelectComponentsLabel2=Selecciona los componentes que quieres instalar; Quita los componentes que no deseas que sean instalados. Haga click a Siguiente para continuar.
FullInstallation=Instalaci�n Completa
; if possible don't translate 'Compact' as 'Minimal' (I mean 'Minimal' in your language)
CompactInstallation=Instalaci�n Compacta
CustomInstallation=Instalaci�n Personalizada
NoUninstallWarningTitle=Los componentes existen
NoUninstallWarning=El Instalador ha detectado que los siguientes componentes existen en tu computadora:%n%n%1%n%nDeseleccionando estos componentes no los va a desinstalar.%n%n�Deseas continuar de todas maneras?
ComponentSize1=%1 KB
ComponentSize2=%1 MB
ComponentsDiskSpaceMBLabel=La seleccion que tienes requiere al menos [mb] MB de espacio de disco duro.

; *** "Select Additional Tasks" wizard page
WizardSelectTasks=Seleccionar Tareas Adicionales
SelectTasksDesc=�Cuales tareas adicionales deseas que sean ejecutadas?
SelectTasksLabel2=Selecciona las tareas adicionales que deseas que la instalaci�n ejecute [name], despu�s haz click a Siguiente.

; *** "Select Start Menu Folder" wizard page
WizardSelectProgramGroup=Selecciona el Menu Inicio
SelectStartMenuFolderDesc=�Donde debe la instalaci�n poner los accesos directos del programa?
SelectStartMenuFolderLabel3=El Instalador va a crear los accesos directs del programa en el Menu Inicio.
SelectStartMenuFolderBrowseLabel=Para continuar, haz click a Siguiente. Si deseas seleccionar una carpeta diferente , haga click a Explorar.
NoIconsCheck=&No crear iconos
MustEnterGroupName=Debes dar un nombre a la carpeta.
GroupNameTooLong=El nombre de la carpeta o el destino es muy largo.
InvalidGroupName=El nombre de la carpeta es invalido.
BadGroupName=El nombre de la carpeta no debe incluir los siguientes caracteres:%n%n%1
NoProgramGroupCheck2=&No crear la carpeta en el Menu Inicio

; *** "Ready to Install" wizard page
WizardReady=Listo para instalar
ReadyLabel1=Instalador esta listo para instalar [name] en tu computadora.
ReadyLabel2a=Haga click a Instalar para continuar con la instalaci�n, o haga click a Atr�s si quieres checar alguna configuraci�n o cambiarla.
ReadyLabel2b=Haga click a  Instalar para continuar con la instalaci�n.
ReadyMemoUserInfo=Informaci�n de Usuario:
ReadyMemoDir=Locaci�n de destino:
ReadyMemoType=Tipo de instalaci�n:
ReadyMemoComponents=Components seleccionados:
ReadyMemoGroup=Carpeta Menu Inicio:
ReadyMemoTasks=Tareas Adicionales:

; *** "Preparing to Install" wizard page
WizardPreparing=Preparando para Instalar
PreparingDesc=El Instalador esta preparando para instalar [name] en tu computadora.
PreviousInstallNotCompleted=La instalaci�n/Desinstalaci�n del siguiente programa no ha sido completado. Vas a necesitar reiniciar tu computadora para completar con la Instalaci�n.%n%nDespu�s de reiniciar tu computadora, ejecuta la instalaci�n para completar la instalaci�n de [name].
CannotContinue=La instalaci�n. Por favor haz click a Cancelar.

; *** "Installing" wizard page
WizardInstalling=Instalando
InstallingLabel=Por favor espere mientras se instala [name] en tu computadora.

; *** "Setup Completed" wizard page
FinishedHeadingLabel=Completando Instalaci�n de [name] 
FinishedLabelNoIcons=El Instalador ha terminado de instalar [name] en tu computadora.
FinishedLabel=El Instalador ha terminado de instalar [name] en tu computadora. La aplicaci�n puede ser lanzada seleccionando los iconos instalados.
ClickFinish=Haz click aqu� para cerrar el instalador.
FinishedRestartLabel=Para completar la instalaci�n de [name], El Instalador debe reiniciar tu computadora. �Desear�as reiniciar ahora?
FinishedRestartMessage=Para completar la instalaci�n de [name],  El Instalador debe reiniciar tu computadora.%n%n�Desear�as reiniciar ahora?
ShowReadmeCheck=Si, Desear�a leer el archivo README
YesRadio=&Si, reiniciar mi computadora ahora
NoRadio=&No, Voy a reiniciar mi computadora despu�s
; used for example as 'Run MyProg.exe'
RunEntryExec=Correr %1
; used for example as 'View Readme.txt'
RunEntryShellExec=Ver %1

; *** "Setup Needs the Next Disk" stuff
ChangeDiskTitle=El Instalador necesita el siguiente disco
SelectDiskLabel2=Por favor inserta el disco %1 y haz click a OK.%n%nSi los archivos pueden ser encontrados en una carpeta otra que la que se muestra abajo, da el destino correcto o haz click a Explorar.
PathLabel=&Path:
FileNotInDir2=El archivo "%1" no pudo ser localizado en "%2". Por favor inserta el disco correcto o selecciona otra carpeta.
SelectDirectoryLabel=Por favor especifica la locaci�n del siguiente disco.

; *** Installation phase messages
SetupAborted=La Instalaci�n no ha sido completa.%n%nPor favor arregla el problema y vuelve a correr el Instalador.
EntryAbortRetryIgnore=Haz click a volver a tratar, Ignorar para proceder de todas maneras, o Abortar para cancelar instalaci�n.

; *** Installation status messages
StatusCreateDirs=Creando directorios...
StatusExtractFiles=Extrayendo archivos...
StatusCreateIcons=Creando accesos directos...
StatusCreateIniEntries=Creado entradas INI...
StatusCreateRegistryEntries=Creando entradas de registro...
StatusRegisterFiles=Registrando archivos...
StatusSavingUninstall=Guardando informaci�n de desinstalaci�n...
StatusRunProgram=Terminando instalci�n...
StatusRollback=Quitando cambios...

; *** Misc. errors
ErrorInternal2=Error Interno: %1
ErrorFunctionFailedNoCode=%1 fall�
ErrorFunctionFailed=%1 fall�; codigo %2
ErrorFunctionFailedWithMessage=%1 fallado; codigo %2.%n%3
ErrorExecutingProgram=No fue posible ejecutar archivo:%n%1

; *** Registry errors
ErrorRegOpenKey=Error al abrir clave de registro:%n%1\%2
ErrorRegCreateKey=Error creando clave de registro:%n%1\%2
ErrorRegWriteKey=Error escribiendo a clave de registro:%n%1\%2

; *** INI errors
ErrorIniEntry=Error creando entrada INI a archivo"%1".

; *** File copying errors
FileAbortRetryIgnore=Haga click a volver a tratar, Ignorar para saltarse este archivo (no recomendado), o Abortar para cancelar la instalaci�n.
FileAbortRetryIgnore2=Haga click a volver a tratar, Ignorar para proceder de cualquier forma (no recomendado), o Abortar para cancelar la instalaci�n.
SourceIsCorrupted=El archivo fuente esta corrupto
SourceDoesntExist=El archivo fuente %1 no existe
ExistingFileReadOnly=El archivo existente esta marcado como solo lectura.%n%Haga click a volver a tratar para remover el atributo y tratar de nuevo, Ignorar para pasarde este archivo, o Abortar para cancelar la instalaci�n 
ErrorReadingExistingDest=Ocurrio un error al tratar de leer el archivo existente:
FileExists=Este archivo ya existe.%n%�Deseas que la instalaci�n lo reescriba?
ExistingFileNewer=El archivo existente es mas nuevo que el que la instalacon esta tratando de instalar. It is recommended that you keep the existing file.%n%nDo you want to keep the existing file?
ExistingFileNewer=El archivo existente es m�s reciente del que se est� tratando de instalar.  Se recomienda que mantenga el archivo existente.%n%n�Desea mantener el archivo existente?
ErrorChangingAttr=Ocurri� un error al tratar de cambiar los atributos del archivo:
ErrorCreatingTemp=Ocurri� un error al tratar de crear un archivo en el directorio destino:
ErrorCopying=Ocurri� un error al tratar de copiar un archivo:
ErrorReplacingExistingFile==Ocurri� un error al tratar de reemplazar el archivo existente:
ErrorReadingSource=Ocurri� un error al tratar de leer el archivo fuente:
ErrorRenamingTemp=Ocurri� un error al tratar de renombrar un archivo en el directorio destino:
ErrorRegisterServer=Imposible registrar el DLL/OCX: %1
ErrorRegisterServerMissingExport=El m�dulo de registro DllRegisterServer no fu� encontrado
ErrorRegisterTypeLib=Imposible registrar el tipo de librer�a: %1

; *** Post-installation errors
ErrorOpeningReadme=Ocurri� un error al tratar de abrir el archivo LEEME.
ErrorRestartingComputer=El instalador no pudo reiniciar la computadora.  H�galo manualmente.

; *** Uninstaller messages
UninstallNotFound=El archivo %1 no existe.  No se puede desinstalar.
UninstallOpenError=El archivo %1 no pudo ser abierto.  No se puede desinstalar.
UninstallUnsupportedVer=La bit�cora de desinstalaci�n %1 est� en un formato no reconocido por esta versi�n del desinstalador.  No es posible desinstalar.
UninstallUnknownEntry=Una entrada desconocida (%1) fu� encontrada en la bit�cora de desinstalaci�n.
ConfirmUninstall=�Est� seguro que desea eliminar completamente %1 y todos sus componentes?
OnlyAdminCanUninstall=Este sistema solo puede ser desinstalado por un usuario con privilegios de administraci�n.
UninstallStatusLabel=Por favor espere mientras %1 es eliminado de su computadora.
UninstalledAll=%1 fu� exitosamente eliminado de su computadora.
UninstalledMost=%1 desinstalaci�n terminada.%n%nAlgunos elementos no pudieron ser eliminados.  Deber�n ser borrados manualmente.
UninstalledAndNeedsRestart=Para completar la desinstalaci�n de %1, su computadora deber� ser reiniciada.%n%n�Desea hacerlo ahora?
UninstallDataCorrupted="%1" archivo corrupto.  No se puede desinstalar.

; *** Uninstallation phase messages
; *** Mensajes de fase de desinstalaci�n
ConfirmDeleteSharedFileTitle=�Borrar los archivos compartidos?
ConfirmDeleteSharedFile2=El sistema indica que el siguiente archivo compartido ya no es usado por ning�n programa. �Desea que la desinstalaci�n borre este archivo compartido?%n%nSi alg�n programa a�n lo utiliza y es borrado, ese programa no funcionar� correctamente.  Si no est� seguro, elija No.  Dejar el archivo en su sistema no causar� ning�n da�o.
SharedFileNameLabel=Nombre del archivo:
SharedFileLocationLabel=Ubicaci�n:
WizardUninstalling=Estado de la desinstalaci�n
StatusUninstalling=Desinstalando %1...

; The custom messages below aren't used by Setup itself, but if you make
; use of them in your scripts, you'll want to translate them.

[CustomMessages]

NameAndVersion=%1 versi�n %2
AdditionalIcons=Iconos adiccionales:
CreateDesktopIcon=Mostrar/Quitar icono de &Escritorio
CreateQuickLaunchIcon=Mostrar/Quitar icono de &Inicio R�pido
ProgramOnTheWeb=%1 en la web
UninstallProgram=Desinstalar %1
LaunchProgram=Lanzar %1
AssocFileExtension=&Asociar %1 con %2 extensi�n de archivo
AssocingFileExtension=Asociando %1 con %2 extensi�n de archivo...


