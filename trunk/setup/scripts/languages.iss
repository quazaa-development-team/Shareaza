; This sub-script defines all languages to be compiled
; WARNING: Do not change this file's encoding

[Languages]
; Use compiler's built in ISL file to patch up holes in ISL collection and specify localized license files
; Note: first language specified is default > English

Name: "en"; MessagesFile: "compiler:Default.isl,setup\isl\default.isl"; LicenseFile: "setup/license/default.rtf"
Name: "nl"; MessagesFile: "compiler:Default.isl,setup\isl\dutch.isl"; LicenseFile: "setup/license/dutch.rtf"
Name: "lt"; MessagesFile: "compiler:Default.isl,setup\isl\lithuanian.isl"; LicenseFile: "setup/license/lithuanian.rtf"
Name: "de"; MessagesFile: "compiler:Default.isl,setup\isl\german.isl"; LicenseFile: "setup/license/German.rtf"
Name: "pt"; MessagesFile: "compiler:Default.isl,setup\isl\portuguese-std.isl"; LicenseFile: "setup/license/portuguese-braz.rtf"
Name: "it"; MessagesFile: "compiler:Default.isl,setup\isl\italian.isl"; LicenseFile: "setup/license/italian.rtf"
Name: "no"; MessagesFile: "compiler:Default.isl,setup\isl\norwegian.isl"; LicenseFile: "setup/license/default.rtf"
Name: "af"; MessagesFile: "compiler:Default.isl,setup\isl\afrikaans.isl"; LicenseFile: "setup/license/afrikaans.rtf"
Name: "br"; MessagesFile: "compiler:Default.isl,setup\isl\portuguese-braz.isl"; LicenseFile: "setup/license/portuguese-braz.rtf"
Name: "fr"; MessagesFile: "compiler:Default.isl,setup\isl\french.isl"; LicenseFile: "setup/license/default.rtf"
Name: "es"; MessagesFile: "compiler:Default.isl,setup\isl\spanish.isl"; LicenseFile: "setup/license/spanish.rtf"
Name: "ru"; MessagesFile: "compiler:Default.isl,setup\isl\russian.isl"; LicenseFile: "setup/license/russian.rtf"
Name: "gr"; MessagesFile: "compiler:Default.isl,setup\isl\greek.isl"; LicenseFile: "setup/license/greek.rtf"
Name: "hu"; MessagesFile: "compiler:Default.isl,setup\isl\hungarian.isl"; LicenseFile: "setup/license/default.rtf"

[Files]
; Install default remote
Source: "Remote\*"; DestDir: "{app}\Remote"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Components: not language
; Install localized remote
; English
Source: "Remote\*"; DestDir: "{app}\Remote"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: en; Components: language
; Dutch
Source: "Remote-localized\dutch\*"; DestDir: "{app}\Remote"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: nl; Components: language
; Lithuanian
Source: "Remote-localized\lithuanian\*"; DestDir: "{app}\Remote"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: lt; Components: language
; German
Source: "Remote\*"; DestDir: "{app}\Remote"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: de; Components: language
; Portuguese std
Source: "Remote-localized\portuguese\*"; DestDir: "{app}\Remote"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: pt; Components: language
; Italian
Source: "Remote-localized\italian\*"; DestDir: "{app}\Remote"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: it; Components: language
; Norwegian
Source: "Remote-localized\norwegian\*"; DestDir: "{app}\Remote"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: no; Components: language
; Afrikaans
Source: "Remote\*"; DestDir: "{app}\Remote"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: af; Components: language
; Portuguese braz
Source: "Remote-localized\portuguese\*"; DestDir: "{app}\Remote"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: br; Components: language
; French
Source: "Remote-localized\french\*"; DestDir: "{app}\Remote"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: fr; Components: language
; Spanish
Source: "Remote\*"; DestDir: "{app}\Remote"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: es; Components: language
; Russian
Source: "Remote-localized\Russian\*"; DestDir: "{app}\Remote"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: ru; Components: language
; Greek
Source: "Remote\*"; DestDir: "{app}\Remote"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: gr; Components: language
; Hungarian
Source: "Remote-localized\hungarian\*"; DestDir: "{app}\Remote"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: hu; Components: language

; Install default license
Source: "setup\license\default.rtf"; DestDir: "{app}\Uninstall"; DestName: "license.rtf"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Components: not language
; Install localized license
; English
Source: "setup\license\default.rtf"; DestDir: "{app}\Uninstall"; DestName: "license.rtf"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: en; Components: language
; Dutch
Source: "setup\license\dutch.rtf"; DestDir: "{app}\Uninstall"; DestName: "license.rtf"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: nl; Components: language
; Lithuanian
Source: "setup\license\lithuanian.rtf"; DestDir: "{app}\Uninstall"; DestName: "license.rtf"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: lt; Components: language
; German
Source: "setup\license\german.rtf"; DestDir: "{app}\Uninstall"; DestName: "license.rtf"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: de; Components: language
; Portuguese std
Source: "setup\license\portuguese-braz.rtf"; DestDir: "{app}\Uninstall"; DestName: "license.rtf"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: pt; Components: language
; Italian
Source: "setup\license\italian.rtf"; DestDir: "{app}\Uninstall"; DestName: "license.rtf"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: it; Components: language
; Norwegian
Source: "setup\license\default.rtf"; DestDir: "{app}\Uninstall"; DestName: "license.rtf"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: no; Components: language
; Afrikaans
Source: "setup\license\afrikaans.rtf"; DestDir: "{app}\Uninstall"; DestName: "license.rtf"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: af; Components: language
; Portuguese braz
Source: "setup\license\portuguese-braz.rtf"; DestDir: "{app}\Uninstall"; DestName: "license.rtf"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: br; Components: language
; French
Source: "setup\license\default.rtf"; DestDir: "{app}\Uninstall"; DestName: "license.rtf"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: fr; Components: language
; Spanish
Source: "setup\license\spanish.rtf"; DestDir: "{app}\Uninstall"; DestName: "license.rtf"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: es; Components: language
; Russian
Source: "setup\license\russian.rtf"; DestDir: "{app}\Uninstall"; DestName: "license.rtf"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: ru; Components: language
; Greek
Source: "setup\license\greek.rtf"; DestDir: "{app}\Uninstall"; DestName: "license.rtf"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: gr; Components: language
; Hungarian
Source: "setup\license\default.rtf"; DestDir: "{app}\Uninstall"; DestName: "license.rtf"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: hu; Components: language

[CustomMessages]
; This section specifies phrazes and words not specified in the ISL files
; Avoid customizing the ISL files since they will change with each version of Inno Setup.
; English:
components_plugins=Plugins
components_skins=Skins
components_languages=Languages
tasks_allusers=All users
tasks_selectusers=Install %1 for:
tasks_currentuser=%1 only
tasks_multisetup=Enable multi-user support
run_skinexe=Running skin installation...
reg_incomingchat=Incoming chat message
reg_apptitle=Shareaza Ultimate File Sharing
icons_license=License
icons_uninstall=Uninstall
icons_downloads=Downloads
dialog_shutdown=%1 is currently running. Would you like %1 to be shutdown so the installation can continue ?
; Dutch:
nl.components_plugins=Plugins
nl.components_skins=Skins
nl.components_languages=Talen
nl.tasks_allusers=Alle gebruikers
nl.tasks_selectusers=Installeer %1 voor:
nl.tasks_currentuser=Aleen %1
nl.tasks_multisetup=Ondersteuning voor meerdere gebruikers inschakelen
nl.run_skinexe=Skin installatie uitvoeren...
nl.reg_incomingchat=Nieuw chat bericht
nl.reg_apptitle=Shareaza Ultimate File Sharing
nl.icons_license=Gebruiksovereenkomst
nl.icons_uninstall=Verwijderen
nl.icons_downloads=Downloads
nl.dialog_shutdown=%1 is momenteel open. Wil je %1 afsluiten zodat de installatie verder kan gaan?
; Lithuanian:
lt.components_plugins=Papildiniai
lt.components_skins=Apvalkalai
lt.components_languages=Kalbos
lt.tasks_allusers=Visiems vartotojams
lt.tasks_selectusers=�diegti �%1� �iems vartotojams:
lt.tasks_currentuser=Tik vartotojui %1
lt.tasks_multisetup=�galinti keli� vartotoj� palaikym�
lt.run_skinexe=Vykdoma apvalkalo s�ranka...
lt.reg_incomingchat=Gaunama �inut� pokalbiui
lt.reg_apptitle=Shareaza � geriausia programa byl� mainams
lt.icons_license=Licencin� sutartis
lt.icons_uninstall=Pa�alinti
lt.icons_downloads=Atsisiuntimai
lt.dialog_shutdown=Ar norite nutraukti �%1� darb�?
; German
de.components_plugins=Plugins
de.components_skins=Skins
de.components_languages=Sprachen
de.tasks_allusers=Alle Benutzer
de.tasks_selectusers=Installieren %1 f�r:
de.tasks_currentuser=Nur f�r %1
de.tasks_multisetup=Mehrbenutzerunterst�tzung aktivieren
de.run_skinexe=Skin Installer einrichten...
de.reg_incomingchat=Eingehende Chat Nachricht
de.reg_apptitle=Shareaza Ultimate File Sharing
de.icons_license=Lizenz
de.icons_uninstall=Shareaza deinstallieren
de.icons_downloads=Downloads
de.dialog_shutdown=%1 wird zur Zeit ausgef�hrt. Wollen Sie %1 beenden, um mit der Installation fortzufahren ?
; Portuguese std
pt.components_plugins=Plugins
pt.components_skins=Skins
pt.components_languages=Languages
pt.tasks_allusers=All users
pt.tasks_selectusers=Install %1 for:
pt.tasks_currentuser=%1 only
pt.tasks_multisetup=Enable multi-user support
pt.run_skinexe=Running skin installation...
pt.reg_incomingchat=Incoming chat message
pt.reg_apptitle=Shareaza Ultimate File Sharing
pt.icons_license=License
pt.icons_uninstall=Uninstall
pt.icons_downloads=Downloads
pt.dialog_shutdown=%1 is currently running. Would you like %1 to be shutdown so the installation can continue ?
; Italian
it.components_plugins=Plugins
it.components_skins=Skins
it.components_languages=Lingua
it.tasks_allusers=Tutti gli utenti
it.tasks_selectusers=Installa %1 per:
it.tasks_currentuser=Solo %1
it.tasks_multisetup=Abilita supporto multi utente
it.run_skinexe=St� installando le skin...
it.reg_incomingchat=Messaggio di chat in arrivo
it.reg_apptitle=Shareaza, il programma definitivo di P2P
it.icons_license=Licenza
it.icons_uninstall=Disinstalla
it.icons_downloads=Downloads
it.dialog_shutdown=%1 is currently running. Would you like %1 to be shutdown so the installation can continue ?
; Norwegian
no.components_plugins=Plugins
no.components_skins=Skins
no.components_languages=Spr�k
no.tasks_allusers=Alle brukere
no.tasks_selectusers=Installer %1 for:
no.tasks_currentuser=Kun %1
no.tasks_multisetup=Flere brukere
no.run_skinexe=Kj�rer skin installasjon...
no.reg_incomingchat=Innkommende melding
no.reg_apptitle=Shareaza Ultimate File Sharing
no.icons_license=Lisens
no.icons_uninstall=Uninstall
no.icons_downloads=Downloads
no.dialog_shutdown=%1 is currently running. Would you like %1 to be shutdown so the installation can continue ?
; Afrikaans
af.components_plugins=Inpropprogramme
af.components_skins=Omslagte
af.components_languages=Tale
af.tasks_allusers=Alle gebruikers van hierdie rekenaar
af.tasks_selectusers=Installeer %1 vir die volgende gebruikers:
af.tasks_currentuser=Vir %1 alleenlik
af.tasks_multisetup=Skakel ondersteuning vir veelvuldige gebruikers aan
af.run_skinexe=Hardloop omslagte installasie...
af.reg_incomingchat=Inkomende Geselsie-boodskap
af.reg_apptitle=Shareaza Ultimate File Sharing
af.icons_license=Lisensie-ooreenkoms
af.icons_uninstall=De�nstalleer
af.icons_downloads=Aflaaie
af.dialog_shutdown=%1 is currently running. Would you like %1 to be shutdown so the installation can continue ?
; Portuguese braz
br.components_plugins=Plugins
br.components_skins=Peles
br.components_languages=Linguagens
br.tasks_allusers=Todos os Usu�rios
br.tasks_selectusers=Instalar %1 para:
br.tasks_currentuser=%1 apenas
br.tasks_multisetup=Ativar suporte para v�rios usu�rios
br.run_skinexe=Instalando as Peles...
br.reg_incomingchat=Nova mensagem no chat
br.reg_apptitle=Shareaza o Compartilhador de Arquivos Definitivo
br.icons_license=Licen�a
br.icons_uninstall=Desinstalar
br.icons_downloads=Downloads
br.dialog_shutdown=Voc� deseja fechar o %1?
; French
fr.components_plugins=Plugins
fr.components_skins=Skins
fr.components_languages=Langues
fr.tasks_allusers=Tous les utilisateurs
fr.tasks_selectusers=Installer %1 pour:
fr.tasks_currentuser=%1 seulement
fr.tasks_multisetup=Activer le support multi-utilisateurs
fr.run_skinexe=Installation de la skin en cours...
fr.reg_incomingchat=R�ception d'un message chat
fr.reg_apptitle=Shareaza Ultimate File Sharing
fr.icons_license=Licence
fr.icons_uninstall=D�sinstaller
fr.icons_downloads=T�l�chargements
fr.dialog_shutdown=%1 is currently running. Would you like %1 to be shutdown so the installation can continue ?
; Spanish
es.components_plugins=Plugins
es.components_skins=Skins
es.components_languages=Lenguages
es.tasks_allusers=Todos los usuarios
es.tasks_selectusers=Instalar %1 para:
es.tasks_currentuser=%1 solamente
es.tasks_multisetup=Habilitar soporte multi-usuario
es.run_skinexe=Instalando Skin...
es.reg_incomingchat=Hay un mensaje de chat entrante
es.reg_apptitle=Shareaza Ultimate File Sharing
es.icons_license=Licencia
es.icons_uninstall=Desinstalar
es.icons_downloads=Descargas
es.dialog_shutdown=%1 is currently running. Would you like %1 to be shutdown so the installation can continue ?
; Russian
ru.components_plugins=������
ru.components_skins=������
ru.components_languages=�����
ru.tasks_allusers=���� �������������
ru.tasks_selectusers=���������� %1 ���:
ru.tasks_currentuser=������ ��� %1
ru.tasks_multisetup=��������� ��������� ���������� �������������
ru.run_skinexe=��� ��������� ������...
ru.reg_incomingchat=�������� ��������� ��� ����
ru.reg_apptitle=Shareaza - ��������� ��� ������ �������
ru.icons_license=��������
ru.icons_uninstall=�������������
ru.icons_downloads=��������
ru.dialog_shutdown=������ �� ��������� ������ %1?
; Greek
gr.components_plugins=Plugins
gr.components_skins=Skins
gr.components_languages=�������
gr.tasks_allusers=���� �� �������
gr.tasks_selectusers=����������� %1 ���:
gr.tasks_currentuser=%1 ����
gr.tasks_multisetup=������������ ��� �������� ��������� �������
gr.run_skinexe=Running ����������� ��� skin...
gr.reg_incomingchat=��� ������ chat
gr.reg_apptitle=Shareaza Ultimate File Sharing
gr.icons_license=�����
gr.icons_uninstall=�������������
gr.icons_downloads=���������
gr.dialog_shutdown=������ �� ����������� ��� ���������� ��� %1?
; Hungarian
hu.components_plugins=Plugins
hu.components_skins=Skins
hu.components_languages=Languages
hu.tasks_allusers=All users
hu.tasks_selectusers=Install %1 for:
hu.tasks_currentuser=%1 only
hu.tasks_multisetup=Enable multi-user support
hu.run_skinexe=Running skin installation...
hu.reg_incomingchat=Incoming chat message
hu.reg_apptitle=Shareaza Ultimate File Sharing
hu.icons_license=License
hu.icons_uninstall=Uninstall
hu.icons_downloads=Downloads
hu.dialog_shutdown=%1 is currently running. Would you like %1 to be shutdown so the installation can continue ?

