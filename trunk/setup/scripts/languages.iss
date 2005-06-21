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
Name: "hu"; MessagesFile: "compiler:Default.isl,setup\isl\hungarian.isl"; LicenseFile: "setup/license/hungarian.rtf"
Name: "chs"; MessagesFile: "compiler:Default.isl,setup\isl\chinese-simp.isl"; LicenseFile: "setup/license/chinese.rtf"
Name: "sv"; MessagesFile: "compiler:Default.isl,setup\isl\swedish.isl"; LicenseFile: "setup/license/swedish.rtf"
Name: "fi"; MessagesFile: "compiler:Default.isl,setup\isl\finnish.isl"; LicenseFile: "setup/license/finnish.rtf"
Name: "heb"; MessagesFile: "compiler:Default.isl,setup\isl\hebrew.isl"; LicenseFile: "setup/license/hebrew.rtf"

[Files]
#ifndef debug
; Install default remote
Source: "Remote\en\*"; DestDir: "{app}\Remote"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Components: not language
; Install localized remote
; English
Source: "Remote\en\*"; DestDir: "{app}\Remote"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: en; Components: language
; Dutch
Source: "Remote\nl\*"; DestDir: "{app}\Remote"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: nl; Components: language
; Lithuanian
Source: "Remote\lt\*"; DestDir: "{app}\Remote"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: lt; Components: language
; German
Source: "Remote\en\*"; DestDir: "{app}\Remote"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: de; Components: language
; Portuguese std
Source: "Remote\pt\*"; DestDir: "{app}\Remote"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: pt; Components: language
; Italian
Source: "Remote\it\*"; DestDir: "{app}\Remote"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: it; Components: language
; Norwegian
Source: "Remote\no\*"; DestDir: "{app}\Remote"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: no; Components: language
; Afrikaans
Source: "Remote\en\*"; DestDir: "{app}\Remote"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: af; Components: language
; Portuguese braz
Source: "Remote\pt\*"; DestDir: "{app}\Remote"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: br; Components: language
; French
Source: "Remote\fr\*"; DestDir: "{app}\Remote"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: fr; Components: language
; Spanish
Source: "Remote\es\*"; DestDir: "{app}\Remote"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: es; Components: language
; Russian
Source: "Remote\ru\*"; DestDir: "{app}\Remote"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: ru; Components: language
; Greek
Source: "Remote\en\*"; DestDir: "{app}\Remote"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: gr; Components: language
; Hungarian
Source: "Remote\hu\*"; DestDir: "{app}\Remote"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: hu; Components: language
; Chinese Simp
Source: "Remote\chs\*"; DestDir: "{app}\Remote"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: chs; Components: language
; Swedish
Source: "Remote\sv\*"; DestDir: "{app}\Remote"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: sv; Components: language
; Finnish
Source: "Remote\en\*"; DestDir: "{app}\Remote"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: fi; Components: language
; Hebrew
Source: "Remote\en\*"; DestDir: "{app}\Remote"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: fi; Components: language

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
Source: "setup\license\hungarian.rtf"; DestDir: "{app}\Uninstall"; DestName: "license.rtf"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: hu; Components: language
; Chinese Simp
Source: "setup\license\chinese.rtf"; DestDir: "{app}\Uninstall"; DestName: "license.rtf"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: chs; Components: language
; Swedish
Source: "setup\license\swedish.rtf"; DestDir: "{app}\Uninstall"; DestName: "license.rtf"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: sv; Components: language
; Finnish
Source: "setup\license\finnish.rtf"; DestDir: "{app}\Uninstall"; DestName: "license.rtf"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: fi; Components: language
; Hebrew
Source: "setup\license\hebrew.rtf"; DestDir: "{app}\Uninstall"; DestName: "license.rtf"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: heb; Components: language

; Install default filter
Source: "setup\filter\default.dat"; DestDir: "{app}\Data"; DestName: "AdultFilter.dat"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Components: not language
; Install localized filter
; English
Source: "setup\filter\default.dat"; DestDir: "{app}\Data"; DestName: "AdultFilter.dat"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: en; Components: language
; Dutch
Source: "setup\filter\dutch.dat"; DestDir: "{app}\Data"; DestName: "AdultFilter.dat"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: nl; Components: language
; Lithuanian
Source: "setup\filter\lithuanian.dat"; DestDir: "{app}\Data"; DestName: "AdultFilter.dat"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: lt; Components: language
; German
Source: "setup\filter\german.dat"; DestDir: "{app}\Data"; DestName: "AdultFilter.dat"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: de; Components: language
; Portuguese std
Source: "setup\filter\default.dat"; DestDir: "{app}\Data"; DestName: "AdultFilter.dat"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: pt; Components: language
; Italian
Source: "setup\filter\italian.dat"; DestDir: "{app}\Data"; DestName: "AdultFilter.dat"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: it; Components: language
; Norwegian
Source: "setup\filter\default.dat"; DestDir: "{app}\Data"; DestName: "AdultFilter.dat"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: no; Components: language
; Afrikaans
Source: "setup\filter\default.dat"; DestDir: "{app}\Data"; DestName: "AdultFilter.dat"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: af; Components: language
; Portuguese braz
Source: "setup\filter\default.dat"; DestDir: "{app}\Data"; DestName: "AdultFilter.dat"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: br; Components: language
; French
Source: "setup\filter\french.dat"; DestDir: "{app}\Data"; DestName: "AdultFilter.dat"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: fr; Components: language
; Spanish
Source: "setup\filter\spanish.dat"; DestDir: "{app}\Data"; DestName: "AdultFilter.dat"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: es; Components: language
; Russian
Source: "setup\filter\russian.dat"; DestDir: "{app}\Data"; DestName: "AdultFilter.dat"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: ru; Components: language
; Greek
Source: "setup\filter\greek.dat"; DestDir: "{app}\Data"; DestName: "AdultFilter.dat"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: gr; Components: language
; Hungarian
Source: "setup\filter\default.dat"; DestDir: "{app}\Data"; DestName: "AdultFilter.dat"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: hu; Components: language
; Chinese Simp
Source: "setup\filter\chinese-simpl.dat"; DestDir: "{app}\Data"; DestName: "AdultFilter.dat"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: chs; Components: language
; Swedish
Source: "setup\filter\swedish.dat"; DestDir: "{app}\Data"; DestName: "AdultFilter.dat"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: sv; Components: language
; Finnish
Source: "setup\filter\default.dat"; DestDir: "{app}\Data"; DestName: "AdultFilter.dat"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: fi; Components: language
; Hebrew
Source: "setup\filter\hebrew.dat"; DestDir: "{app}\Data"; DestName: "AdultFilter.dat"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Languages: heb; Components: language
#endif

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
tasks_firewall=Add an exception to the Windows Firewall
;tasks_deleteoldsetup=Delete old installers
run_skinexe=Running skin installation...
reg_incomingchat=Incoming chat message
reg_apptitle=Shareaza Ultimate File Sharing
icons_license=License
icons_uninstall=Uninstall
icons_downloads=Downloads
dialog_shutdown=%1 is currently running. Would you like %1 to be shutdown so the installation can continue?
dialog_firewall=Setup failed to add Shareaza to the Windows Firewall.%nPlease add Shareaza to the exception list manually.
page_viruswarning_text=When using the internet, you should always ensure you have an up-to-date virus scanner to protect you from trojans, worms, and other malicious programs. You can find list of good virus scanners and other security tips to protect your computer by following this link:
page_viruswarning_title=Virus Warning
page_viruswarning_subtitle=Do you have an AntiVirus program installed?
page_viruswarning_link=http://www.shareaza.com/securityhelp
page_viruswarning_destination=http://www.shareaza.com/securityhelp/
; Don't copy these last 2 messages, they are just links.
; Dutch:
nl.components_plugins=Plugins
nl.components_skins=Skins
nl.components_languages=Talen
nl.tasks_allusers=Alle gebruikers
nl.tasks_selectusers=Installeer %1 voor:
nl.tasks_currentuser=Aleen %1
nl.tasks_multisetup=Ondersteuning voor meerdere gebruikers inschakelen
nl.tasks_firewall=Een uitzondering aan de Windows Firewall toevoegen
;nl.tasks_deleteoldsetup=Oude installatieprogramma's wissen
nl.run_skinexe=Skin installatie uitvoeren...
nl.reg_incomingchat=Nieuw chat bericht
nl.reg_apptitle=Shareaza Ultimate File Sharing
nl.icons_license=Gebruiksovereenkomst
nl.icons_uninstall=Verwijderen
nl.icons_downloads=Downloads
nl.dialog_shutdown=%1 is momenteel open. Wil je %1 afsluiten zodat de installatie verder kan gaan?
nl.dialog_firewall=Het installatieprogramma kon Shareaza niet toevoegen aan de Windows Firewall.%nVoeg Shareaza alstublieft manueel toe aan de uitzonderingenlijst.
nl.page_viruswarning_text=Als u het internet gebruikt moet u een recente virusscanner gebruiken om u te beschermen tegen virussen, wormen en andere kwaadaardige programma's. U kan een lijst van virusscanners en andere veiligheidstips vinden om uw computer the beschermen door deze link te volgen:
nl.page_viruswarning_title=Virus Waarschuwing
nl.page_viruswarning_subtitle=Heeft u een antivirus programma ge�nstalleerd?
; Lithuanian:
lt.components_plugins=Papildiniai
lt.components_skins=Apvalkalai
lt.components_languages=Kalbos
lt.tasks_allusers=Visiems vartotojams
lt.tasks_selectusers=�diegti �%1� �iems vartotojams:
lt.tasks_currentuser=Tik vartotojui %1
lt.tasks_multisetup=�galinti keli� vartotoj� palaikym�
lt.tasks_firewall=Prid�ti prie Windows ugniasien�s i�im�i� s�ra�o
;lt.tasks_deleteoldsetup=Delete old installers
lt.run_skinexe=Vykdoma apvalkalo s�ranka...
lt.reg_incomingchat=Gaunama �inut� pokalbiui
lt.reg_apptitle=Shareaza � geriausia programa byl� mainams
lt.icons_license=Licencin� sutartis
lt.icons_uninstall=Pa�alinti
lt.icons_downloads=Atsisiuntimai
lt.dialog_shutdown=�%1� �iuo metu dirba. Ar norite nutraukti �%1� darb�, tam kad b�t� galima t�sti �diegim�?
lt.dialog_firewall=�diegimo programai nepavyko prid�ti �Shareaza� prie Windows ugniasien�s i�im�i� s�ra�o.%nPrid�kite j� � �� s�ra�� rankiniu b�du.
lt.page_viruswarning_text=Visada, kai naudojat�s Internetu, �sitikinkite, jog turite naujausi� virus� skener�, tam kad b�tum�te apsaugoti nuo trojan�, kirmin� ir kitoki� kenk�ji�k� program�. J�s galite rasti ger� virus� skeneri� s�ra�� ir kitokius kompiuterio apsaugojimo patarimus nu�j� �iuo adresu:
lt.page_viruswarning_title=�sp�jimas apie virusus
lt.page_viruswarning_subtitle=Ar J�s turite �sidieg� antivirusin� program�?
; German
de.components_plugins=Plugins
de.components_skins=Skins
de.components_languages=Sprachen
de.tasks_allusers=Alle Benutzer
de.tasks_selectusers=Installieren %1 f�r:
de.tasks_currentuser=Nur f�r %1
de.tasks_multisetup=Mehrbenutzerunterst�tzung aktivieren
de.tasks_firewall=Eine Ausnahme zur Windows Firewall hinzuf�gen
;de.tasks_deleteoldsetup=Delete old installers
de.run_skinexe=Skin Installer einrichten...
de.reg_incomingchat=Eingehende Chat Nachricht
de.reg_apptitle=Shareaza Ultimate File Sharing
de.icons_license=Lizenz
de.icons_uninstall=Shareaza deinstallieren
de.icons_downloads=Downloads
de.dialog_shutdown=%1 wird zur Zeit ausgef�hrt. Wollen Sie %1 beenden, um mit der Installation fortzufahren?
de.dialog_firewall=Setup konnte Shareaza nicht zur Windows Firewall hinzuf�gen.%nBitte tragen Sie Shareaza manuell in die Ausnahmenliste ein.
de.page_viruswarning_text=Wenn Sie das Internet benutzen, sollten Sie stets einen aktuellen Virenscanner installiert haben, der ihren Computer vor Trojanern, W�rmern und anderen b�sartigen Programmen besch�tzt. Sie finden eine Liste guter Virenscanner und andere Tipps, wie Sie ihren Computer sch�tzen k�nnen, unter folgendem Link:
de.page_viruswarning_title=Virenwarnung
de.page_viruswarning_subtitle=Haben Sie ein Antivirenprogramm installiert?
; Portuguese std
pt.components_plugins=Plugins
pt.components_skins=Peles
pt.components_languages=Linguagens
pt.tasks_allusers=Todos os usu�rios
pt.tasks_selectusers=Instalar %1 para:
pt.tasks_currentuser=somente %1
pt.tasks_multisetup=Acionar o suporte a v�rios usu�rios
pt.tasks_firewall=Adicionar exce��o ao Firewall do Windows
;pt.tasks_deleteoldsetup=Delete old installers
pt.run_skinexe=Instalando Pele...
pt.reg_incomingchat=Mensagem de chat
pt.reg_apptitle=Shareaza Compartilhamento de Arquivos Incompar�vel
pt.icons_license=Licen�a
pt.icons_uninstall=Desintalar
pt.icons_downloads=Downloads
pt.dialog_shutdown=O %1 est� sendo executado. Voc� gostaria que o %1 fosse fechado para que a instala��o continue?
pt.dialog_firewall=Setup failed to add Shareaza to the Windows Firewall.%nPlease add Shareaza to the exception list manually.
pt.page_viruswarning_text=When using the internet, you should always ensure you have an up-to-date virus scanner to protect you from trojans, worms, and other malicious programs. You can find list of good virus scanners and other security tips to protect your computer by following this link:
pt.page_viruswarning_title=Virus Warning
pt.page_viruswarning_subtitle=Do you have an AntiVirus program installed?
; Italian
it.components_plugins=Plugins
it.components_skins=Skins
it.components_languages=Lingue
it.tasks_allusers=Tutti gli utenti
it.tasks_selectusers=Installa %1 per:
it.tasks_currentuser=Solo %1
it.tasks_multisetup=Abilita supporto multi utente
it.tasks_firewall=Aggiungi un'eccezione a Windows Firewall
;it.tasks_deleteoldsetup=Delete old installers
it.run_skinexe=Sto installando le skin...
it.reg_incomingchat=Messaggio di chat in arrivo
it.reg_apptitle=Shareaza, il programma definitivo di P2P
it.icons_license=Licenza
it.icons_uninstall=Disinstalla
it.icons_downloads=Downloads
it.dialog_shutdown=%1 � attualmente in esecuzione. Vuoi che %1 sia chiuso cos� l'installazione pu� continuare?
it.dialog_firewall=Impossibile aggiungere Shareaza a Windows Firewall.%nAggiungi Shareaza alla lista delle eccezioni manualmente.
it.page_viruswarning_text=Quando usi internet, dovresti sempre assicurarti di aver un antivirus aggiornato per proteggerti dai trojan, worm e dagli altri programmi malevoli. Puoi trovare una lista di buoni antivirus e altri suggerimenti di sicurezza per proteggere il tuo computer seguendo questo link:
it.page_viruswarning_title=Attenzione ai virus
it.page_viruswarning_subtitle=Hai installato un programma antivirus?
; Norwegian
no.components_plugins=Plugins
no.components_skins=Skins
no.components_languages=Spr�k
no.tasks_allusers=Alle brukere
no.tasks_selectusers=Installer %1 for:
no.tasks_currentuser=Kun %1
no.tasks_multisetup=Flere brukere
no.tasks_firewall=Lag nytt unntak i Windows brannmur
;no.tasks_deleteoldsetup=Delete old installers
no.run_skinexe=Kj�rer skin installasjon...
no.reg_incomingchat=Innkommende melding
no.reg_apptitle=Shareaza Ultimate File Sharing
no.icons_license=Lisens
no.icons_uninstall=Uninstall
no.icons_downloads=Downloads
no.dialog_shutdown=%1 kj�rer. �nsker du at %1 avsluttes slik at installasjonen kan fortsette?
no.dialog_firewall=Installasjonen klarte ikke � lage unntak for Shareaza i Windows Brannmuren. %nVennligst legg til shareaza i brannmurens unntak manuelt.
no.page_viruswarning_text=N�r du bruker internett b�r du alltid ha et oppdatert antivirus-program, for � beskytte deg fra trojaner, ormer, og annen skadelig programvare. Du kan finne en liste over gode antivirus-prgrammer og andre sikkerhetstips, for � beskytte din datamaskin, ved � f�lge denne linken:
no.page_viruswarning_title=Virusadvarsel
no.page_viruswarning_subtitle=Har du et antivirus-program installert?
; Afrikaans
af.components_plugins=Inpropprogramme
af.components_skins=Omslagte
af.components_languages=Tale
af.tasks_allusers=Alle gebruikers van hierdie rekenaar
af.tasks_selectusers=Installeer %1 vir die volgende gebruikers:
af.tasks_currentuser=Vir %1 alleenlik
af.tasks_multisetup=Skakel ondersteuning vir veelvuldige gebruikers aan
af.tasks_firewall=Voeg 'n uitsondering by die Windows Netskans
;af.tasks_deleteoldsetup=Delete old installers
af.run_skinexe=Hardloop omslagte installasie...
af.reg_incomingchat=Inkomende Geselsie-boodskap
af.reg_apptitle=Shareaza Ultimate File Sharing
af.icons_license=Lisensie-ooreenkoms
af.icons_uninstall=De�nstalleer
af.icons_downloads=Aflaaie
af.dialog_shutdown=%1 is op die oomblik besig om te loop. Wil jy graag %1 sluit sodat die installasie kan voortgaan?
af.dialog_firewall=Die Opsteller kon nie Shareaza by die Windows netskans uitsonderings voeg nie.%nVoeg Shareaza asseblief met die hand op die uitsonderingslys.
af.page_viruswarning_text=Maak altyd seker dat jy 'n opgedateerde anti-virus program ge�nstalleer het wanneer jy die internet gebruik, om jou rekenaar te beskerm teen virusse, wurms, en ander ongewenste programme. Jy kan 'n lys van goeie anti-virus programme en ander sekuriteitswenke oor hoe om jou rekenaar te beskerm verkry deur die volgende skakel te volg:
af.page_viruswarning_title=Virus Waarskuwing
af.page_viruswarning_subtitle=Het jy 'n Anti-Virus program ge�nstalleer?
; Portuguese braz
br.components_plugins=Plugins
br.components_skins=Peles
br.components_languages=Linguagens
br.tasks_allusers=Todos os Usu�rios
br.tasks_selectusers=Instalar %1 para:
br.tasks_currentuser=%1 apenas
br.tasks_multisetup=Ativar suporte para v�rios usu�rios
br.tasks_firewall=Adicionar exce��o ao Firewall do Windows
;br.tasks_deleteoldsetup=Delete old installers
br.run_skinexe=Instalando as Peles...
br.reg_incomingchat=Nova mensagem no chat
br.reg_apptitle=Shareaza o Compartilhador de Arquivos Definitivo
br.icons_license=Licen�a
br.icons_uninstall=Desinstalar
br.icons_downloads=Downloads
br.dialog_shutdown=Voc� deseja fechar o %1?
br.dialog_firewall=A instala��o falhou ao tentar adicionar o Shareaza � lista de exce��es do Firewall do Windows.%nPor favor adicione manualmente o Shareaza � lista.
br.page_viruswarning_text=Ao usar a Internet voc� deve sempre manter seu Anti-V�rus atualizado, para proteger contra v�rus, worms, cavalos-de-tr�ia e outros programas perigosos. Voc� encontra uma lista de bons anti-v�rus e dicas de seguran�a entrando no seguinte endere�o:
br.page_viruswarning_title=Aviso sobre V�rus
br.page_viruswarning_subtitle=Voc� tem um programa anti-v�rus instalado?
; French
fr.components_plugins=Plugins
fr.components_skins=Skins
fr.components_languages=Langues
fr.tasks_allusers=Tous les utilisateurs
fr.tasks_selectusers=Installer %1 pour:
fr.tasks_currentuser=%1 seulement
fr.tasks_multisetup=Activer le support multi-utilisateurs
fr.tasks_firewall=Ajouter une exception au Pare-feu Windows
;fr.tasks_deleteoldsetup=Delete old installers
fr.run_skinexe=Installation de la skin en cours...
fr.reg_incomingchat=R�ception d'un message chat
fr.reg_apptitle=Shareaza Ultimate File Sharing
fr.icons_license=Licence
fr.icons_uninstall=D�sinstaller
fr.icons_downloads=T�l�chargements
fr.dialog_shutdown=%1 est en cours d'ex�cution. Voulez-vous quitter %1 pour que l'installation puisse se poursuivre?
fr.dialog_firewall=L'installation n'a pas pu ajouter Shareaza au Pare-feu Windows.%nVeuillez ajouter Shareaza manuellement � la liste des exceptions.
fr.page_viruswarning_text=Lorsque vous utilisez internet, vous devriez toujours vous assurer que vous avez un scanner de virus � jour pour vous prot�ger des troyens (trojans), vers (worms), et autres programmes malveillants. Vous pouvez trouver une liste de bons antivirus et conseils de s�curit� pour prot�ger votre ordinateur en suivant ce lien:
fr.page_viruswarning_title=Avertissement sur les virus
fr.page_viruswarning_subtitle=Avez-vous un antivirus install�?
; Spanish
es.components_plugins=Plugins
es.components_skins=Skins
es.components_languages=Lenguages
es.tasks_allusers=Todos los usuarios
es.tasks_selectusers=Instalar %1 para:
es.tasks_currentuser=%1 solamente
es.tasks_multisetup=Habilitar soporte multi-usuario
es.tasks_firewall=Agregar una excepci�n al Firewall de Windows
;es.tasks_deleteoldsetup=Delete old installers
es.run_skinexe=Instalando Skin...
es.reg_incomingchat=Hay un mensaje de chat entrante
es.reg_apptitle=Shareaza Ultimate File Sharing
es.icons_license=Licencia
es.icons_uninstall=Desinstalar
es.icons_downloads=Descargas
es.dialog_shutdown=%1 se encuentra ejecut�ndose. �Deseas que %1 sea cerrado para que la instalaci�n pueda continuar?
es.dialog_firewall=La instalaci�n fallo al agregar la excepci�n de Shareaza al cortafuego Firewall.%n Por favor h�galo manualmente.
es.page_viruswarning_text=Cuando estas usando Internet, debes siempre asegurarte que tienes un antivirus actualizado hasta la fecha para protegerte de troyanos, gusanos, y otros programas maliciosos. Puedes encontrar una lista de buenos antivirus y sugerencias de seguridad para proteger tu computadora en la siguiente direcci�n:
es.page_viruswarning_title=Peligro de Virus
es.page_viruswarning_subtitle=�Tienes un programa antivirus instalado?
; Russian
ru.components_plugins=������
ru.components_skins=������
ru.components_languages=�����
ru.tasks_allusers=���� �������������
ru.tasks_selectusers=���������� %1 ���:
ru.tasks_currentuser=������ ��� %1
ru.tasks_multisetup=��������� ��������� ���������� �������������
ru.tasks_firewall=�������� � ������ ���������� ���������� Windows
;ru.tasks_deleteoldsetup=Delete old installers
ru.run_skinexe=��� ��������� ������...
ru.reg_incomingchat=�������� ��������� ��� ����
ru.reg_apptitle=Shareaza - ��������� ��� ������ �������
ru.icons_license=��������
ru.icons_uninstall=�������������
ru.icons_downloads=��������
ru.dialog_shutdown=%1 � ������ ������ ��������. ������ �� ��������� ������ %1, ����� ���������� ���������?
ru.dialog_firewall=��������� ��������� �� ������ �������� Shareaza � ������ ���������� ����������� Windows.%n����������, �������� �� � ���� ������ �������.
ru.page_viruswarning_text=������, ����� ����������� ����������, ��������������, ��� � ��� ���� �������� ������ ��� �������, ����� �������� ��������� �� �������, ������ � ������ ������������� ��������. �� ������ ����� ������ ������� �������� ��� ������� � ������ ������ � ������ ���������� �� ����� ������:
ru.page_viruswarning_title=��������������� � �������
ru.page_viruswarning_subtitle=������ �� �� ������������� ������������ ���������?
; Greek
gr.components_plugins=Plugins
gr.components_skins=Skins
gr.components_languages=�������
gr.tasks_allusers=���� �� �������
gr.tasks_selectusers=����������� %1 ���:
gr.tasks_currentuser=%1 ����
gr.tasks_multisetup=������������ ��� �������� ��������� �������
gr.tasks_firewall=���� ��� �������� ��� ������ ���������� ��� Windows
;gr.tasks_deleteoldsetup=Delete old installers
gr.run_skinexe=Running ����������� ��� skin...
gr.reg_incomingchat=��� ������ chat
gr.reg_apptitle=Shareaza Ultimate File Sharing
gr.icons_license=�����
gr.icons_uninstall=�������������
gr.icons_downloads=���������
gr.dialog_shutdown=�� %1 ����� ������. ������ �� ����������� ��� ����������� ��� %1 ��� �� ���������� � �����������?
gr.dialog_firewall=� ����������� ��� ������������ ������� �� ��������� �� Shareaza ��� Windows Firewall. % �������� ��������� �� Shareaza ���� exception ����� �����������
gr.page_viruswarning_text=���� �������������� �� internet, �� ������ ����� �� ����� ��� ��������� ���������� ��� ���� ����������� ��� �� ��� ����������� ��� ������ ��� ���� ���������� �����������. �������� �� ������ ��� ����� �� ���� ����������� ���������� ��� ���� ��� ���� ��������� ��� �� ������������ ��� ���������� ��� ������������ ����� ��� ��������:
gr.page_viruswarning_title=������������� ��� ��
gr.page_viruswarning_subtitle=����� ��� ��������� ���������� ��� ���� �������������?
; Hungarian
hu.components_plugins=Pluginek
hu.components_skins=Kin�zetek
hu.components_languages=Nyelvek
hu.tasks_allusers=Minden felhaszn�l�
hu.tasks_selectusers=Megadott felhasz�l�:
hu.tasks_currentuser=Jelenlegi felhaszn�l�
hu.tasks_multisetup=T�bbfelhaszn�l�s m�d enged�lyez�se
hu.tasks_firewall=Felv�tel a Windows t�zfal kiv�teleihez
;hu.tasks_deleteoldsetup=Delete old installers
hu.run_skinexe=Kin�zet telep�t�se folyamatban...
hu.reg_incomingchat=Bej�v� chat �zenet
hu.reg_apptitle=Shareaza f�jlmegoszt�
hu.icons_license=Licensz
hu.icons_uninstall=T�rl�s
hu.icons_downloads=Let�lt�sek
hu.dialog_shutdown=A %1 jelenleg fut. Be akarod z�rni a programot, hogy a telep�t�s folytat�dhasson?
hu.dialog_firewall=A telep�to nem tudta hozz�adni a Shareaz�t a Windows tuzfal kiv�teleihez.%nManu�lisan kell hozz�adni a kiv�telekhez.
hu.page_viruswarning_text=Ha az internetet haszn�lod, mindig legyen f�ltelep�tve egy, a legfrissebb v�rusadatb�zissal rendelkez� antiv�rus program, ami megv�d a f�rgekt�l, tr�jai �s egy�b k�rt�kony programokt�l. Ha k�veted ezt a linket, sok j� v�ruskeres�t tal�lhatsz �s hasznos tippeket kaphatsz a sz�m�t�g�p v�delm�r�l:
hu.page_viruswarning_title=V�rusvesz�ly
hu.page_viruswarning_subtitle=Van feltelep�tett antiv�rus programod?
; Chinese Simp
chs.components_plugins=���
chs.components_skins=Ƥ��
chs.components_languages=����
chs.tasks_allusers=�����û�
chs.tasks_selectusers=��װ %1 Ϊ:
chs.tasks_currentuser=�� %1
chs.tasks_multisetup=���ö��û�֧��
chs.tasks_firewall=���һ�����⵽ Windows ����ǽ
;chs.tasks_deleteoldsetup=Delete old installers
chs.run_skinexe=��װƤ��...
chs.reg_incomingchat=����������Ϣ
chs.reg_apptitle=Shareaza �ռ��ļ�����
chs.icons_license=���
chs.icons_uninstall=ж��
chs.icons_downloads=����
chs.dialog_shutdown=%1 �������С���ϣ���ر� %1 �Ա������װ��
chs.dialog_firewall=��װ��� Shareaza �� Windows ����ǽʧ�ܡ�%n�뽫 Shareaza �ֶ�����������б�
chs.page_viruswarning_text=�����û�����ʱ������Ҫȷ����ӵ�����µĲ���ɨ������Ա���������ľ�������������������ֺ����������������������ҵ��ϺõĲ���ɨ��������б��Լ������������ļ�����İ�ȫ����:
chs.page_viruswarning_title=��������
chs.page_viruswarning_subtitle=����װ�˷������������
; Swedish
sv.components_skins=Skinn
sv.components_languages=Spr�k
sv.tasks_allusers=Alla anv�ndare
sv.tasks_selectusers=Installera %1 f�r:
sv.tasks_currentuser=%1 endast
sv.tasks_multisetup=Aktivera st�d f�r flera anv�ndare
sv.tasks_firewall=L�gg till ett undantag till Windows brandv�gg
;sv.tasks_deleteoldsetup=Delete old installers
sv.run_skinexe=K�r skinninstallation...
sv.reg_incomingchat=Inkommande chattmeddelande
sv.reg_apptitle=Shareaza ultimat fildelning
sv.icons_license=Licens
sv.icons_uninstall=Avinstallera
sv.icons_downloads=Nedladdningar
sv.dialog_shutdown=%1 k�rs f�r tillf�llet. Vill du att %1 ska st�ngas ned s� att installationen kan forts�tta?
sv.dialog_firewall=Setup failed to add Shareaza to the Windows Firewall.%nPlease add Shareaza to the exception list manually.
sv.page_viruswarning_text=When using the internet, you should always ensure you have an up-to-date virus scanner to protect you from trojans, worms, and other malicious programs. You can find list of good virus scanners and other security tips to protect your computer by following this link:
sv.page_viruswarning_title=Virus Warning
sv.page_viruswarning_subtitle=Do you have an AntiVirus program installed?
; Finnish
fi.components_plugins=Laajennukset
fi.components_skins=Ulkoasut
fi.components_languages=Kielet
fi.tasks_allusers=Kaikille k�ytt�jille
fi.tasks_selectusers=Asenna %1 k�ytt�jille:
fi.tasks_currentuser=%1 vain
fi.tasks_multisetup=Asenna kaikille koneen k�ytt�jille
fi.tasks_firewall=Lis�� poikkeus Windowsin palomuuriin
;fi.tasks_deleteoldsetup=Poista vanhat asennukset
fi.run_skinexe=K�ynniss� ulkoasujen asennus...
fi.reg_incomingchat=Tuleva keskusteluviesti
fi.reg_apptitle=Shareaza jako-ohjelma
fi.icons_license=Lisenssi
fi.icons_uninstall=Poista
fi.icons_downloads=Lataukset
fi.dialog_shutdown=%1 on t�ll� hetkell� k�ynniss�. Haluatko ett� %1 suljetaan jotta asennus voisi jatkua?
fi.dialog_firewall=Asentaja ep�onnistui lis�tess��n Shareazaa Windowsiin Firewall.%nOle hyv� ja lis�� Shareaza poikkeuslistaan manuaalisesti.
fi.page_viruswarning_text=Kun k�yt�t interneti�, sinun tulee aina varmistaa ett� sinulla on viimeisimm�t p�ivitykset virusohjelmissasi jotka suojaavat sinua troijalaisilta, madoilta, ja muilta haittaohjelmilta. L�yd�t hyv�n listan hyvist� virusohjelmista ja turvallisuusvinkkej� seuraavista linkeist�:
fi.page_viruswarning_title=Virus Varoitus
fi.page_viruswarning_subtitle=Onko sinulla AntiVirus ohjelmaa asennettuna?
; Hebrew
heb.components_plugins=������
heb.components_skins=������
heb.components_languages=����
heb.tasks_allusers=�� ��������
heb.tasks_selectusers=���� �� %1 ����
heb.tasks_currentuser=%1 ��
heb.tasks_multisetup=���� ����� �������� ������
heb.tasks_firewall=���� ��� ����� ��� ������� ����
;heb.tasks_deleteoldsetup=��� ������ �����
heb.run_skinexe=���� ����� ������...
heb.reg_incomingchat=����� �'�� �����
heb.reg_apptitle=����� ������ ����������� �� ����
heb.icons_license=�����
heb.icons_uninstall=��� �����
heb.icons_downloads=������
heb.dialog_shutdown=?���� %1 ���� ��� �� ���� ����� �� %1 �� ������� ���� �����
heb.dialog_firewall=������ ����� ������ �� ���� �� ���� ���%n��� ���� �� ���� ������ ������� ����� ��� ����� ����
heb.page_viruswarning_text=����/� ����� �������� ����� ���� ����� ������ ���� ����-����� ������ ����� ���� �������/������/������, ������ �� ����-������� ������ ����� ����� ��� ������ ���:
heb.page_viruswarning_title=����� �����
heb.page_viruswarning_subtitle=?��� �� �� ����� ����-����� ������
