; *** Inno Setup version 4.2.2+ Portuguese (Standard) messages ***
;
; Author: NARS (http://nars.cjb.net)
; Last update: 29 Apr 2004
;
; To download user-contributed translations of this file, go to:
;   http://www.jrsoftware.org/is3rdparty.php
;
; Note: When translating this text, do not add periods (.) to the end of
; messages that didn't have them already, because on those messages Inno
; Setup adds the periods automatically (appending a period would result in
; two periods being displayed).
;
; $jrsoftware: issrc/Files/Languages/portuguese-braz.isl,v 1.4 2004/05/18 20:46:55 nars Exp $

[LangOptions]
LanguageName=Portugu<00EA>s (Brasileiro)
LanguageID=$0416
LanguageCodePage=1252

[Messages]

; *** Application titles
SetupAppTitle=Instala��o
SetupWindowTitle=%1 - Instala��o
UninstallAppTitle=Desinstala��o
UninstallAppFullTitle=%1 - Desinstala��o

; *** Misc. common
InformationTitle=Informa��o
ConfirmTitle=Confirma��o
ErrorTitle=Erro

; *** SetupLdr messages
SetupLdrStartupMessage=Esse procedimento instalar� o %1. Deseja continuar?
LdrCannotCreateTemp=N�o foi poss�vel criar um arquivo tempor�rio. Instala��o abortada
LdrCannotExecTemp=N�o foi poss�vel executar o arquivo na pasta tempor�ria. Instala��o abortada

; *** Startup error messages
LastErrorMessage=%1.%n%nErro %2: %3
SetupFileMissing=O arquivo %1 n�o foi encontrado na pasta de instala��o. Corrija o problema ou obtenha uma nova c�pia do programa.
SetupFileCorrupt=Os arquivos de instala��o est�o corrompidos. Obtenha uma nova c�pia do programa.
SetupFileCorruptOrWrongVer=Os arquivos de instala��o est�o corrompidos, ou s�o incompat�veis com esta vers�o do Assistente de Instala��o. Corrija o problema ou obtenha uma nova c�pia do programa.
NotOnThisPlatform=Este programa n�o pode ser executado no %1.
OnlyOnThisPlatform=Este programa deve ser executado no %1.
WinVersionTooLowError=Este programa necessita do %1 vers�o %2 ou mais recente.
WinVersionTooHighError=Este programa n�o pode ser instalado no %1 vers�o %2 ou mais recente.
AdminPrivilegesRequired=Deve iniciar sess�o como administrador para instalar este programa.
PowerUserPrivilegesRequired=Deve iniciar sess�o como administrador ou membro do grupo de Super Usu�rios para instalar este programa.
SetupAppRunningError=O Assistente de Instala��o detectou que o %1 est� em execu��o. Feche-o e de seguida clique em OK para continuar, ou clique em Cancelar para cancelar a instala��o.
UninstallAppRunningError=O Assistente de Desinstala��o detectou que o %1 est� em execu��o. Feche-o e de seguida clique em OK para continuar, ou clique em Cancelar para cancelar a desinstala��o.

; *** Misc. errors
ErrorCreatingDir=O Assistente de Instala��o n�o consegue criar a pasta "%1"
ErrorTooManyFilesInDir=N�o � poss�vel criar um arquivo na pasta "%1" porque ela cont�m muitos arquivos

; *** Setup common messages
ExitSetupTitle=Terminar a instala��o
ExitSetupMessage=A instala��o n�o est� completa. Se terminar agora, o programa n�o ser� instalado.%n%nMais tarde poder� executar novamente este Assistente de Instala��o e concluir a instala��o.%n%nDeseja terminar a instala��o?
AboutSetupMenuItem=&Sobre...
AboutSetupTitle=Sobre o Assistente de Instala��o
AboutSetupMessage=%1 vers�o %2%n%3%n%n%1 home page:%n%4
AboutSetupNote=Traduzido por Lukas Taves

; *** Buttons
ButtonBack=< &Anterior
ButtonNext=&Pr�ximo >
ButtonInstall=&Instalar
ButtonOK=OK
ButtonCancel=Cancelar
ButtonYes=&Sim
ButtonYesToAll=Sim para &todos
ButtonNo=&N�o
ButtonNoToAll=N�&o para todos
ButtonFinish=&Concluir
ButtonBrowse=&Procurar...
ButtonWizardBrowse=P&rocurar...
ButtonNewFolder=&Criar Nova Pasta

; *** "Select Language" dialog messages
SelectLanguageTitle=Selecione o Idioma do Assistente de Instala��o
SelectLanguageLabel=Selecione o idioma para usar durante a Instala��o:

; *** Common wizard text
ClickNext=Clique em Pr�ximo para continuar ou em Cancelar para cancelar a instala��o.
BeveledLabel=
BrowseDialogTitle=Procurar Pasta
BrowseDialogLabel=Selecione uma pasta na lista abaixo e clique em OK.
NewFolderName=Nova Pasta

; *** "Welcome" wizard page
WelcomeLabel1=Bem-vindo ao Assistente de Instala��o do [name]
WelcomeLabel2=O Assistente de Instala��o ir� instalar o [name/ver] em seu computador.%n%n� recomendado fechar todas as outras aplica��es antes de continuar.

; *** "Password" wizard page
WizardPassword=Senha
PasswordLabel1=Esta instala��o est� protegida por senha.
PasswordLabel3=Insira a senha e depois clique em Pr�ximo para continuar. Na senha existe diferen�a entre mai�sculas e min�sculas.
PasswordEditLabel=&Senha:
IncorrectPassword=A senha que introduziu n�o est� correta. Tente novamente.

; *** "License Agreement" wizard page
WizardLicense=Licen�a de contrato
LicenseLabel=� importante ler as pr�ximas informa��es antes de continuar.
LicenseLabel3=Leia atentamente o contrato de licen�a a seguir. Os termos do contrato devem ser aceitos para continuar a instala��o.
LicenseAccepted=A&ceito o contrato
LicenseNotAccepted=&N�o aceito o contrato

; *** "Information" wizard pages
WizardInfoBefore=Informa��o
InfoBeforeLabel=� importante ler as informa��es antes de continuar.
InfoBeforeClickLabel=Quando estiver pronto para continuar clique em Pr�ximo.
WizardInfoAfter=Informa��o
InfoAfterLabel=� importante ler as informa��es antes de continuar.
InfoAfterClickLabel=Quando estiver pronto para continuar clique em Pr�ximo.

; *** "User Information" wizard page
WizardUserInfo=Informa��es do usu�rio
UserInfoDesc=Introduza as suas informa��es.
UserInfoName=Nome do &usu�rio:
UserInfoOrg=&Organiza��o:
UserInfoSerial=N�mero de &s�rie:
UserInfoNameRequired=Deve introduzir um nome.

; *** "Select Destination Location" wizard page
WizardSelectDir=Selecione a localiza��o de destino
SelectDirDesc=Onde dever� ser instalado o [name]?
SelectDirLabel3=O [name] ser� instalado na pasta seguinte.
SelectDirBrowseLabel=Para continuar, clique em Pr�ximo. Se desejar selecionar uma pasta diferente, clique em Procurar.
DiskSpaceMBLabel=� necess�rio pelo menos [mb] MB de espa�o livre em disco.
ToUNCPathname=O Assistente de Instala��o n�o pode instalar num caminho do tipo UNC. Se est� tentanado fazer a instala��o numa rede, precisa mapear a unidade de rede.
InvalidPath=� necess�rio indicar o caminho completo com a letra de unidade; por exemplo:%n%nC:\APP%n%nou um caminho UNC no formato:%n%n\\servidor\compartilhado
InvalidDrive=A unidade ou pasta compartilhada UNC selecionada n�o existe ou n�o est� acess�vel. Selecione outra.
DiskSpaceWarningTitle=N�o h� espa�o suficiente no disco
DiskSpaceWarning=O Assistente de Instala��o necessita de pelo menos %1 KB de espa�o livre, mas a unidade seleccionada tem apenas %2 KB dispon�veis.%n%nDeseja continuar de qualquer forma?
DirNameTooLong=O nome ou caminho para a pasta � muito longo.
InvalidDirName=O nome da pasta � inv�lido.
BadDirName32=O nome da pasta n�o pode conter nenhum dos pr�ximos caracteres:%n%n%1
DirExistsTitle=A pasta j� existe
DirExists=A pasta:%n%n%1%n%nj� existe. Gostaria de instalar assim mesmo?
DirDoesntExistTitle=A pasta n�o existe
DirDoesntExist=A pasta:%n%n%1%n%nn�o existe. Gostaria de cri�-la?

; *** "Select Components" wizard page
WizardSelectComponents=Selecione os componentes
SelectComponentsDesc=Quais componentes dever�o ser instalados?
SelectComponentsLabel2=Selecione os componentes que deseja instalar e de-selecione os componentes que n�o queira instalar. Clique em Pr�ximo quando estiver pronto para continuar.
FullInstallation=Instala��o Completa
; if possible don't translate 'Compact' as 'Minimal' (I mean 'Minimal' in your language)
CompactInstallation=Instala��o Compacta
CustomInstallation=Instala��o Personalizada
NoUninstallWarningTitle=Componentes Encontrados
NoUninstallWarning=O Assistente de Instala��o detectou que os pr�ximos componentes est�o instalados no seu computador:%n%n%1%n%nSe de-seleccionar estes componentes eles n�o ser�o desinstalados.%n%nDeseja continuar?
ComponentSize1=%1 KB
ComponentSize2=%1 MB
ComponentsDiskSpaceMBLabel=A sele��o atual necessita de pelo menos [mb] MB de espa�o em disco.

; *** "Select Additional Tasks" wizard page
WizardSelectTasks=Selecione tarefas adicionais
SelectTasksDesc=Que tarefas adicionais dever�o ser executadas?
SelectTasksLabel2=Selecione as tarefas adicionais que deseja que o Assistente de Instala��o execute na instala��o do [name] e em seguida clique em Pr�ximo.

; *** "Select Start Menu Folder" wizard page
WizardSelectProgramGroup=Selecione a pasta do Menu Iniciar
SelectStartMenuFolderDesc=Onde dever�o ser colocados os �cones de atalho do programa?
SelectStartMenuFolderLabel3=Os �cones de atalho do programa ser�o criados na seguinte pasta do Menu Iniciar.
SelectStartMenuFolderBrowseLabel=Para continuar, clique em Pr�ximo. Se desejar selecionar uma pasta diferente, clique em Procurar.
NoIconsCheck=&N�o criar �cones
MustEnterGroupName=� necess�rio nomear a pasta.
GroupNameTooLong=O nome ou caminho para a pasta � muito grande.
InvalidGroupName=O nome da pasta � inv�lido.
BadGroupName=O nome da pasta n�o pode conter nenhum dos pr�ximos caracteres:%n%n%1
NoProgramGroupCheck2=&N�o criar nenhuma pasta no Menu Iniciar

; *** "Ready to Install" wizard page
WizardReady=Pronto para Instalar
ReadyLabel1=O Assistente de Instala��o est� pronto para instalar o [name] no seu computador.
ReadyLabel2a=Clique em Instalar para continuar a instala��o, ou clique em Anterior se desejar rever ou alterar alguma das configura��es.
ReadyLabel2b=Clique em Instalar para continuar a instala��o.
ReadyMemoUserInfo=Informa��es do utilizador:
ReadyMemoDir=Localiza��o de destino:
ReadyMemoType=Tipo de instala��o:
ReadyMemoComponents=Componentes selecionados:
ReadyMemoGroup=Pasta do Menu Iniciar:
ReadyMemoTasks=Tarefas adicionais:

; *** "Preparing to Install" wizard page
WizardPreparing=Preparando-se para instalar
PreparingDesc=Preparando-se para instalar o [name] no seu computador.
PreviousInstallNotCompleted=A instala��o/remo��o de um programa anterior n�o foi completada. Voc� precisa reiniciar o computador para completar essa instala��o.%n%nDepois de reiniciar o computador, execute novamente este Assistente de Instala��o para completar a instala��o do [name].
CannotContinue=A Instala��o n�o pode continuar. Clique em Cancelar para sair.

; *** "Installing" wizard page
WizardInstalling=Instalando
InstallingLabel=Aguarde enquanto o Assistente de Instala��o instala o [name] em seu computador.

; *** "Setup Completed" wizard page
FinishedHeadingLabel=Instala��o do [name] foi conclu�da
FinishedLabelNoIcons=O Assistente de Instala��o concluiu a instala��o do [name] no seu computador.
FinishedLabel=O Assistente de Instala��o concluiu a instala��o do [name] no seu computador. A aplica��o pode ser iniciada atrav�s dos �cones instalados.
ClickFinish=Clique em Concluir para finalizar o Assistente de Instala��o.
FinishedRestartLabel=Para completar a instala��o do [name], o Assistente de Instala��o dever� reiniciar o seu computador. Deseja reiniciar agora?
FinishedRestartMessage=Para completar a instala��o do [name], o Assistente de Instala��o dever� reiniciar o seu computador.%n%nDeseja reiniciar agora?
ShowReadmeCheck=Sim, desejo abrir o arquivo LEIAME
YesRadio=&Sim, desejo reiniciar o computador agora
NoRadio=&N�o, desejo reiniciar o computador mais tarde
; used for example as 'Run MyProg.exe'
RunEntryExec=Executar %1
; used for example as 'View Readme.txt'
RunEntryShellExec=Visualizar %1

; *** "Setup Needs the Next Disk" stuff
ChangeDiskTitle=O Assistente de Instala��o precisa do pr�ximo disco
SelectDiskLabel2=Introduza o disco %1 e clique em OK.%n%nSe os arquivos deste disco estiverem num local diferente do mostrado abaixo, indique o caminho correto ou clique em Procurar.
PathLabel=&Caminho:
FileNotInDir2=O arquivo "%1" n�o foi encontrado em "%2". Introduza o disco correto ou selecione outra pasta.
SelectDirectoryLabel=Indique a localiza��o do pr�ximo disco.

; *** Installation phase messages
SetupAborted=A instala��o n�o est� completa.%n%nCorrija o problema e execute o Assistente de Instala��o novamente.
EntryAbortRetryIgnore=Clique em Repetir para tentar novamente, Ignorar para continuar de qualquer forma, ou Abortar para cancelar a instala��o.

; *** Installation status messages
StatusCreateDirs=Criando pastas...
StatusExtractFiles=Extraindo arquivos...
StatusCreateIcons=Criando atalhos...
StatusCreateIniEntries=Criando entradas em INI...
StatusCreateRegistryEntries=Criando entradas no registo...
StatusRegisterFiles=Registrando arquivos...
StatusSavingUninstall=Guardando informa��es para desinstala��o...
StatusRunProgram=Concluindo a instala��o...
StatusRollback=Anulando as altera��es...

; *** Misc. errors
ErrorInternal2=Erro interno: %1
ErrorFunctionFailedNoCode=%1 falhou
ErrorFunctionFailed=%1 falhou; c�digo %2
ErrorFunctionFailedWithMessage=%1 falhou; c�digo %2.%n%3
ErrorExecutingProgram=N�o � poss�vel executar o arquivo:%n%1

; *** Registry errors
ErrorRegOpenKey=Erro ao abrir a chave de registo:%n%1\%2
ErrorRegCreateKey=Erro ao criar a chave de registo:%n%1\%2
ErrorRegWriteKey=Erro ao escrever na chave de registo:%n%1\%2

; *** INI errors
ErrorIniEntry=Erro ao criar entradas em INI no arquivo "%1".

; *** File copying errors
FileAbortRetryIgnore=Clique em Repetir para tentar novamente, Ignorar para ignorar este arquivo (n�o recomendado), ou Abortar para cancelar a instala��o.
FileAbortRetryIgnore2=Clique em Repetir para tentar novamente, Ignorar para continuar de qualquer forma (n�o recomendado), ou Abortar para cancelar a instala��o.
SourceIsCorrupted=O arquivo de origem est� corrompido
SourceDoesntExist=O arquivo de origem "%1" n�o existe
ExistingFileReadOnly=O arquivo existente tem o atributo "somente leitura".%n%nClique em Repetir para remover o atributo "s� de leitura" e tentar novamente, Ignorar para ignorar este arquivo, ou Abortar para cancelar a instala��o.
ErrorReadingExistingDest=Ocorreu um erro ao tentar ler o arquivo existente:
FileExists=O arquivo j� existe.%n%nDeseja substitu�-lo?
ExistingFileNewer=O arquivo existente � mais recente que o que est� a ser instalado. � recomendado que mantenha o arquivo existente.%n%nDeseja manter o arquivo existente?
ErrorChangingAttr=Ocorreu um erro ao tentar alterar os atributos do arquivo existente:
ErrorCreatingTemp=Ocorreu um erro ao tentar criar um arquivo na pasta de destino:
ErrorReadingSource=Ocorreu um erro ao tentar ler o arquivo de origem:
ErrorCopying=Ocorreu um erro ao tentar copiar um arquivo:
ErrorReplacingExistingFile=Ocorreu um erro ao tentar substituir o arquivo existente:
ErrorRestartReplace=RestartReplace failed:
ErrorRenamingTemp=Ocorreu um erro ao tentar mudar o nome de um arquivo na pasta de destino:
ErrorRegisterServer=N�o � poss�vel registar o DLL/OCX: %1
ErrorRegisterServerMissingExport=Exportador DllRegisterServer export not found
ErrorRegisterTypeLib=Incapaz de registrar o tipo de biblioteca: %1

; *** Post-installation errors
ErrorOpeningReadme=Ocorreu um erro ao tentar abrir o arquivo LEIAME.
ErrorRestartingComputer=O Assistente de Instala��o n�o conseguiu reiniciar o computador. Por favor reinicie manualmente.

; *** Uninstaller messages
UninstallNotFound=O arquivo "%1" n�o existe. N�o � poss�vel desinstalar.
UninstallOpenError=N�o foi poss�vel abrir o arquivo "%1". N�o � poss�vel desinstalar.
UninstallUnsupportedVer=O arquivo do relat�rio de desinstala��o "%1" est� num formato que n�o � reconhecido por esta vers�o do desinstalador. N�o � poss�vel desinstalar
UninstallUnknownEntry=Foi encontrada uma entrada desconhecida (%1) no arquivo do relat�rio de desinstala��o
ConfirmUninstall=Tem a certeza que deseja remover completamente o %1 e todos os seus componentes?
OnlyAdminCanUninstall=Esta desinstala��o s� pode ser realizada por um usu�rio com direitos administrativos.
UninstallStatusLabel=Por favor aguarde enquanto o %1 est� sendo removido de seu computador.
UninstalledAll=O %1 foi removido de seu computador com sucesso.
UninstalledMost=A desinstala��o do %1 est� conclu�da.%n%nAlguns elementos n�o puderam ser removidos. Estes elementos podem ser removidos manualmente.
UninstalledAndNeedsRestart=Para completar a desinstala��o do %1, o computador deve ser reiniciado.%n%nDeseja reiniciar agora?
UninstallDataCorrupted=O arquivo "%1" est� corrompido. N�o � poss�vel desinstalar

; *** Uninstallation phase messages
ConfirmDeleteSharedFileTitle=Remover arquivo compartilhado?
ConfirmDeleteSharedFile2=O sistema indica que o pr�ximo arquivo compartilhado n�o est� sendo utilizado por nenhum outro programa. Deseja remov�-lo?%n%nSe algum programa ainda necessitar deste arquivo, poder� n�o funcionar corretamente depois de o remover. Se n�o tiver a certeza, selecione N�o. Manter o arquivo n�o causar� nenhum problema.
SharedFileNameLabel=Nome do arquivo:
SharedFileLocationLabel=Localiza��o:
WizardUninstalling=Estado da desinstala��o
StatusUninstalling=Desinstalando o %1...

; The custom messages below aren't used by Setup itself, but if you make
; use of them in your scripts, you'll want to translate them.

[CustomMessages]

NameAndVersion=%1 vers�o %2
AdditionalIcons=�cones adicionais:
CreateDesktopIcon=Mostrar um �cone na &�rea de trabalho
CreateQuickLaunchIcon=Mostrar um �cone na barra de &Inicializa��o R�pida
ProgramOnTheWeb=%1 na Web
UninstallProgram=Desinstalar o %1
LaunchProgram=Executar o %1
AssocFileExtension=&Associar o %1 aos arquivos com a extens�o %2
AssocingFileExtension=A associar o %1 aos arquivos com a extens�o %2...
