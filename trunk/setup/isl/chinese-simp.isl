; *** Inno Setup version 4.1.8+ Chinese Simplified messages ***
;
; To download user-contributed translations of this file, go to:
;   http://www.jrsoftware.org/is3rdparty.php
;
; Note: When translating this text, do not add periods (.) to the end of
; messages that didn't have them already, because on those messages Inno
; Setup adds the periods automatically (appending a period would result in
; two periods being displayed).
;
; $jrsoftware: issrc/Files/Default.isl,v 1.53 2004/02/25 01:55:24 jr Exp $

[LangOptions]
LanguageName=Chinese Simplified(PRC)
LanguageID=$0804
LanguageCodePage=936
; If the language you are translating to requires special font faces or
; sizes, uncomment any of the following entries and change them accordingly.
DialogFontName=����
DialogFontSize=9
;WelcomeFontName=����
;WelcomeFontSize=12
TitleFontName=����_gb2312
;TitleFontSize=29
CopyrightFontName=����
CopyrightFontSize=9

[Messages]

; *** Application titles
SetupAppTitle=��װ
SetupWindowTitle=��װ - %1
UninstallAppTitle=ж��
UninstallAppFullTitle=%1 ж��

; *** Misc. common
InformationTitle=��Ϣ
ConfirmTitle=ȷ��
ErrorTitle=����

; *** SetupLdr messages
SetupLdrStartupMessage=������װ %1���Ƿ������
LdrCannotCreateTemp=�޷�������ʱ�ļ�����װ�ж�
LdrCannotExecTemp=�޷�������ʱĿ¼�е��ļ�����װ�ж�

; *** Startup error messages
LastErrorMessage=%1��%n%n���� %2: %3
SetupFileMissing=��װĿ¼���ļ� %1 ��ʧ�����跨�������������������ȡ��װ����ĸ�����
SetupFileCorrupt=��װ�ļ��Ѿ��𻵡���������ȡ��װ����ĸ�����
SetupFileCorruptOrWrongVer=��װ�ļ��Ѿ��𻵣����߰汾�����ݡ����跨�������������������ȡ��װ����ĸ�����
NotOnThisPlatform=�������������� %1��
OnlyOnThisPlatform=��������������� %1��
WinVersionTooLowError=��������Ҫ %1 �汾 %2 ����ߡ�
WinVersionTooHighError=�������ܰ�װ�� %1 �汾 %2 ����ߡ�
AdminPrivilegesRequired=�������Թ���Ա��ݵ�¼���ܰ�װ������
PowerUserPrivilegesRequired=Ҫ��װ�˳����������Թ���Ա�򳬼��û���ĳ�Ա��ݵ�¼��
SetupAppRunningError=��װ�����⵽ %1 �������С�%n%n�����ر������н��̼�������Ȼ�󵥻���ȷ������ť���������¡�ȡ�����˳���װ��
UninstallAppRunningError=ж�س����⵽ %1 �������С�%n%n�����ر������н��̼�������Ȼ�󵥻���ȷ������ť���������¡�ȡ�����˳�ж�ء�

; *** Misc. errors
ErrorCreatingDir=��װ�����޷�����Ŀ¼ "%1"
ErrorTooManyFilesInDir=�޷���Ŀ¼ "%1" �д����ļ������а����ļ�̫��

; *** Setup common messages
ExitSetupTitle=�˳���װ
ExitSetupMessage=��װ��δ��ɡ���������˳����������������װ��%n%n�������Ժ������а�װ��������ɰ�װ���̡�%n%n�Ƿ��˳���װ��
AboutSetupMenuItem=���ڰ�װ(&A)...
AboutSetupTitle=���ڰ�װ
AboutSetupMessage=%1 �汾 %2%n%3%n%n%1 ��ҳ:%n%4
AboutSetupNote=

; *** Buttons
ButtonBack=< ��һ��(&B)
ButtonNext=��һ��(&N) >
ButtonInstall=��װ(&I)
ButtonOK=ȷ��
ButtonCancel=ȡ��
ButtonYes=��(&Y)
ButtonYesToAll=ȫ����(&A)
ButtonNo=��(&N)
ButtonNoToAll=ȫ����(&O)
ButtonFinish=���(&F)
ButtonBrowse=���(&B)...
ButtonWizardBrowse=���(&R)...
ButtonNewFolder=�½��ļ���(&M)

; *** "Select Language" dialog messages
SelectLanguageTitle=ѡ��װ����
SelectLanguageLabel=ѡ���ڰ�װ��������ʹ�õ�����:

; *** Common wizard text
ClickNext=�뵥������һ������������ȡ�����˳���װ��
BeveledLabel=
BrowseDialogTitle=����ļ���
BrowseDialogLabel=�������б���ѡ��һ���ļ��У���������ȷ������
NewFolderName=�½��ļ���

; *** "Welcome" wizard page
WelcomeLabel1=��ӭʹ�� [name] ��װ��
WelcomeLabel2=�˳��򽫰�װ [name/ver] �����ļ�����С�%n%nǿ�ҽ������ڼ�����װ֮ǰ�ر����������������еĳ����Ա��ⰲװ�����п��ܲ������໥��ͻ��

; *** "Password" wizard page
WizardPassword=����
PasswordLabel1=����װ���������뱣����
PasswordLabel3=���������룬Ȼ�󵥻�����һ��������������Դ�Сд���У����������
PasswordEditLabel=����(&P):
IncorrectPassword=�����������Ч�������ԡ�

; *** "License Agreement" wizard page
WizardLicense=ʹ�����Э��
LicenseLabel=�ڼ�����װ֮ǰ�����Ķ��������Ҫ��Ϣ��
LicenseLabel3=����ϸ�Ķ������ʹ�����Э�顣�������ڼ�����װ֮ǰ���ܱ�Э�顣
LicenseAccepted=�ҽ��ܸ�Э��(&A)
LicenseNotAccepted=�Ҳ����ܸ�Э��(&A)

; *** "Information" wizard pages
WizardInfoBefore=��Ϣ
InfoBeforeLabel=�ڼ�����װ֮ǰ�������Ķ��������Ҫ��Ϣ��
InfoBeforeClickLabel=׼���ú��뵥������һ������
WizardInfoAfter=��Ϣ
InfoAfterLabel=�ڰ�װ����֮ǰ�������Ķ��������Ҫ��Ϣ��
InfoAfterClickLabel=׼���ú��뵥������һ������

; *** "User Information" wizard page
WizardUserInfo=�û���Ϣ
UserInfoDesc=������������Ϣ��
UserInfoName=�û�����(&U):
UserInfoOrg=��˾(&O):
UserInfoSerial=���к�(&S)
UserInfoNameRequired=����������һ�����֡�

; *** "Select Destination Location" wizard page
WizardSelectDir=ѡ��Ŀ��λ��
SelectDirDesc=��׼���� [name] ��װ�����
SelectDirLabel3=��װ���򽫰�װ [name] �������ļ��С�
SelectDirBrowseLabel=������װ���뵥������һ�����������ϣ��ѡ�������ļ��У��뵥�����������
DiskSpaceMBLabel=��װ�����������Ҫ [mb] MB ���̿ռ䡣
ToUNCPathname=��װ�����޷�������װ��һ�� UNC ·�����������ȷʵ��Ҫ������װ�������ϣ�������ӳ��һ��������������
InvalidPath=����������һ�������������ŵ�����·��������:%n%nC:\APP%n%n��һ�� UNC ·����ʽ:%n%n\\server\share
InvalidDrive=����ѡ����������� UNC �������ڣ����ǲ��ɴ�ȡ�ġ�������ѡ��
DiskSpaceWarningTitle=���̿��ÿռ䲻��
DiskSpaceWarning=��װ����������Ҫ %1 KB ��ʣ����̿ռ䣬������ѡ���������ֻ�� %2 KB ���á�%n%n�����������Ҫ������װ��
DirNameTooLong=�ļ�������·��������
InvalidDirName=���ļ�������Ч��
BadDirName32=�ļ��������ܰ��������κ�һ���ַ�:%n%n%1
DirExistsTitle=�ļ����Ѿ�����
DirExists=�ļ���:%n%n%1%n%n�Ѿ����ڡ� ��������ζ�Ҫ��װ�����ļ�����
DirDoesntExistTitle=�ļ��в�����
DirDoesntExist=�ļ���:%n%n%1%n%n�����ڡ��Ƿ񴴽����ļ��У�

; *** "Select Components" wizard page
WizardSelectComponents=ѡ�����
SelectComponentsDesc=��׼����װ��Щ�����
SelectComponentsLabel2=ѡ����׼����װ���������������밲װ�������׼���ú󵥻�����һ����������
FullInstallation=��ȫ��װ
; if possible don't translate 'Compact' as 'Minimal' (I mean 'Minimal' in your language)
CompactInstallation=���Ͱ�װ
CustomInstallation=�Զ��尲װ
NoUninstallWarningTitle=����Ѵ���
NoUninstallWarning=��װ�����⵽��������Ѿ����������ļ������:%n%n%1%n%n�����Щ����ᵼ���䲻�ܱ�ж�ء�%n%n��������ζ�Ҫ������װ��
ComponentSize1=%1 KB
ComponentSize2=%1 MB
ComponentsDiskSpaceMBLabel=��ǰѡ��������Ҫ [mb] MB ʣ����̿ռ䡣

; *** "Select Additional Tasks" wizard page
WizardSelectTasks=ѡ�񸽼�����
SelectTasksDesc=��׼��������Щ��������
SelectTasksLabel2=ѡ����׼���ڰ�װ [name] �ڼ�ִ�еĸ�������Ȼ�󵥻�����һ������

; *** "Select Start Menu Folder" wizard page
WizardSelectProgramGroup=ѡ��ʼ�˵��ļ���
SelectStartMenuFolderDesc=׼��������Ŀ�ݷ�ʽ���������
SelectStartMenuFolderLabel3=��װ���������п�ʼ�˵��д�������Ŀ�ݷ�ʽ��
SelectStartMenuFolderBrowseLabel=������װ���뵥������һ�����������ϣ��ѡ�������ļ��У��뵥�����������
NoIconsCheck=�������κ�ͼ��(&D)
MustEnterGroupName=����������һ���ļ�������
GroupNameTooLong=�ļ�������·��������
InvalidGroupName=���ļ�������Ч��
BadGroupName=�ļ��������ܰ������е��κ�һ���ַ�:%n%n%1
NoProgramGroupCheck2=��������ʼ�˵��ļ���(&D)

; *** "Ready to Install" wizard page
WizardReady=׼����װ
ReadyLabel1=��װ������׼���ð�װ [name] �����ļ�����С�
ReadyLabel2a=��������װ����ť��ʼ��װ���򵥻�����һ�������ظ��ĸղŵ����á�
ReadyLabel2b=��������װ����ť��ʼ��װ��
ReadyMemoUserInfo=�û���Ϣ:
ReadyMemoDir=Ŀ��λ��:
ReadyMemoType=��װ����:
ReadyMemoComponents=ѡ�����:
ReadyMemoGroup=��ʼ�˵��ļ���:
ReadyMemoTasks=��������:

; *** "Preparing to Install" wizard page
WizardPreparing=׼����װ
PreparingDesc=��װ������׼���ð�װ [name] �����ļ�����С�
PreviousInstallNotCompleted=��ǰ�ĳ���װ��ɾ��û����ɡ��㽫��Ҫ����������ļ��������ɳ���װ��ɾ����������������ļ����֮����һ������ [name] �İ�װ������ɰ�װ��
CannotContinue=��װ���ܼ����� �뵥����ȡ����ȡ����װ��

; *** "Installing" wizard page
WizardInstalling=���ڰ�װ
InstallingLabel=���ڰ�װ [name] �����ļ�����У���ȴ���

; *** "Setup Completed" wizard page
FinishedHeadingLabel=��װ���
FinishedLabelNoIcons=[name] ���������а�װ��ϡ�
FinishedLabel=[name] ���������а�װ��ϡ�������ѡ���Ѱ�װ�õĳ���ͼ������������
ClickFinish=��������ɡ�������װ��
FinishedRestartLabel=Ҫ������ [name] �İ�װ����������������������Ƿ���������������
FinishedRestartMessage=Ҫ������ [name] �İ�װ���������������������%n%n�Ƿ���������������
ShowReadmeCheck=�ǣ���Ҫ�鿴�����ļ�
YesRadio=�ǣ�������������(&Y)
NoRadio=�����ҽ��Ժ���������(&N)
; used for example as 'Run MyProg.exe'
RunEntryExec=���� %1
; used for example as 'View Readme.txt'
RunEntryShellExec=�鿴 %1

; *** "Setup Needs the Next Disk" stuff
ChangeDiskTitle=��Ҫ��һ�Ŵ���
SelectDiskLabel2=�������� %1 ��������ȷ������%n%n����������ʾ�������װ�ļ�Ҳ���������ļ������ҵ�������������ȷ·���򵥻������������ѡ��
PathLabel=·��(&P):
FileNotInDir2=�ļ���%1�� �����ڡ�%2�� ���ҵ����������ȷ�Ĵ��̻�ѡ��������ļ��С�
SelectDirectoryLabel=��ָ����һ�Ŵ��̵�λ�á�

; *** Installation phase messages
SetupAborted=��װ������ɡ�%n%n���跨���������⣬Ȼ���������а�װ����
EntryAbortRetryIgnore=���������ԡ���ť���ԣ������ԡ�����������������ֹ��ȡ����װ��

; *** Installation status messages
StatusCreateDirs=���ڴ���Ŀ¼...
StatusExtractFiles=����չ���ļ�...
StatusCreateIcons=���ڴ�������ͼ��...
StatusCreateIniEntries=���ڴ��� INI ��Ŀ...
StatusCreateRegistryEntries=���ڴ���ע�����Ŀ...
StatusRegisterFiles=���ڽ����ļ�ע��...
StatusSavingUninstall=���ڱ���ж����Ϣ...
StatusRunProgram=���ڽ�����װ...
StatusRollback=�����ջظı�...

; *** Misc. errors
ErrorInternal2=�ڲ�����: %1
ErrorFunctionFailedNoCode=%1 ʧ��
ErrorFunctionFailed=%1 ʧ�ܣ����� %2
ErrorFunctionFailedWithMessage=%1 ʧ�ܣ����� %2.%n%3
ErrorExecutingProgram=���������ļ�:%n%1

; *** Registry errors
ErrorRegOpenKey=��ע�����������:%n%1\%2
ErrorRegCreateKey=����ע�����������:%n%1\%2
ErrorRegWriteKey=д��ע�����������:%n%1\%2

; *** INI errors
ErrorIniEntry=�����ļ� ��%1�� INI ��Ŀʱ����

; *** File copying errors
FileAbortRetryIgnore=���������ԡ���ť���ԣ������ԡ��������ļ�(������)������ֹ��ȡ����װ��
FileAbortRetryIgnore2=���������ԡ���ť���ԣ������ԡ�����������(������)������ֹ��ȡ����װ��
SourceIsCorrupted=Դ�ļ�����
SourceDoesntExist=Դ�ļ� ��%1�� ������
ExistingFileReadOnly=�Ѵ��ڵ��ļ������Ϊֻ����%n%n���������ԡ������ֻ�����Բ����ԣ������ԡ��������ļ�������ֹ��ȡ����װ��
ErrorReadingExistingDest=�����Զ�ȡ�����ļ�ʱ����:
FileExists=�ļ��Ѿ����ڡ�%n%n���Ƿ�ϣ����װ���򸲸�����
ExistingFileNewer=��Ҫ��װ���ļ��������ļ����ɡ����鱣�������ļ���%n%n���Ƿ�ϣ����������
ErrorChangingAttr=�����Ըı������ļ�����ʱ����:
ErrorCreatingTemp=��������Ŀ��Ŀ¼�д����ļ�ʱ����:
ErrorReadingSource=�����Զ�ȡԴ�ļ�ʱ����:
ErrorCopying=�����Ը����ļ�ʱ����:
ErrorReplacingExistingFile=�������滻�����ļ�ʱ����:
ErrorRestartReplace=���������滻ʧ��:
ErrorRenamingTemp=��������Ŀ��Ŀ¼���ļ�������ʱ����:
ErrorRegisterServer=����ע�� DLL/OCX: %1
ErrorRegisterServerMissingExport=DllRegisterServer ����û�з���
ErrorRegisterTypeLib=����ע�����: %1

; *** Post-installation errors
ErrorOpeningReadme=�����Դ������ļ�ʱ����
ErrorRestartingComputer=��װ����������������������ֶ����С�

; *** Uninstaller messages
UninstallNotFound=�ļ���%1�� �����ڡ�����ж�ء�
UninstallOpenError=���ܴ� "%1" �ļ�������ж�ء�
UninstallUnsupportedVer=ж�ؼ�¼�ļ� ��%1�� �ĸ�ʽ���ܱ��˰汾ж�س���ʶ�𡣲���ж��
UninstallUnknownEntry=ж�ؼ�¼�ļ�����������ʶ�����Ŀ (%1)
ConfirmUninstall=ȷ��Ҫ��ȫɾ�� %1 �������еĲ�����
OnlyAdminCanUninstall=ֻ�����й���ԱȨ�޵��û�����ж�ء�
UninstallStatusLabel=���ڴ����ļ������ж�� %1����ȴ���
UninstalledAll=%1 �Ѿ������ļ�����гɹ�ж�ء�
UninstalledMost=%1 ж����ɡ�%n%nĳЩ��Ŀ�����Ƴ����������ֶ�ɾ����
UninstalledAndNeedsRestart=Ҫ��ȫж�� %1, �����������������ԡ�%n%n��ϣ��������������������
UninstallDataCorrupted=��%1�� �ļ����𡣲���ж��

; *** Uninstallation phase messages
ConfirmDeleteSharedFileTitle=ɾ�������ļ���
ConfirmDeleteSharedFile2=ϵͳ��ʾ���й����ļ������Ѳ��ٱ��κγ���ʹ�á��Ƿ��Ƴ���Щ�����ļ���%n%n���ĳ��������Ȼ�õ���Щ�ļ�������ȴ�ѱ�ɾ�����ó�����ܲ����������С�����㲻��ȷ�������ѡ�񡰷񡱡�����Щ�ļ�������ϵͳ�в������ʲôΣ����
SharedFileNameLabel=�ļ���:
SharedFileLocationLabel=λ��:
WizardUninstalling=ж��״̬
StatusUninstalling=����ж�� %1...

; The custom messages below aren't used by Setup itself, but if you make
; use of them in your scripts, you'll want to translate them.

[CustomMessages]

NameAndVersion=%1 �汾 %2
AdditionalIcons=����ͼ��:
CreateDesktopIcon=��ʾ����ͼ��(&D)
CreateQuickLaunchIcon=��ʾ����������ͼ��(&Q)
ProgramOnTheWeb=%1 ����ҳ
UninstallProgram=ж�� %1
LaunchProgram=���� %1
AssocFileExtension=�� %1 ������ %2 �ļ�����չ��(&A)
AssocingFileExtension=���ڽ� %1 ������ %2 �ļ�����չ��...