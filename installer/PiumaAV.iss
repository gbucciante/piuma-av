; Installer grafico di PiumaAV per Windows (Inno Setup 6.3 o successivo).
;
; Compilazione (lo fa la GitHub Action .github/workflows/installer.yml):
;   python tools/build_release.py stage dist/pkg
;   python tools/make_icon.py dist/piuma.ico
;   iscc /DAppVersion=0.6.1 installer\PiumaAV.iss      -> dist\PiumaAV-0.6.1-Setup.exe
;
; L'installer copia il pacchetto in C:\Program Files\PiumaAV\setup ed esegue
; install\windows\install.ps1 (lo stesso script di INSTALLA.bat), mostrando i
; passaggi nella finestra. Il disinstallatore esegue uninstall.ps1.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef PkgDir
  #define PkgDir "..\dist\pkg"
#endif
#ifndef IconFile
  #define IconFile "..\dist\piuma.ico"
#endif

[Setup]
AppId={{9FC97467-C009-4EB9-B572-808F737AA603}
AppName=PiumaAV
AppVersion={#AppVersion}
AppVerName=PiumaAV {#AppVersion}
AppPublisher=Progetto PiumaAV
AppPublisherURL=https://github.com/gbucciante/piuma-av
AppSupportURL=https://github.com/gbucciante/piuma-av/issues
AppUpdatesURL=https://github.com/gbucciante/piuma-av/releases
VersionInfoVersion={#AppVersion}
VersionInfoDescription=Installazione di PiumaAV
; install.ps1 usa sempre C:\Program Files\PiumaAV: la cartella non si sceglie
DefaultDirName={autopf}\PiumaAV
DisableDirPage=yes
UsePreviousAppDir=no
DefaultGroupName=PiumaAV
DisableProgramGroupPage=yes
PrivilegesRequired=admin
; Modalita' 64 bit: PowerShell a 64 bit vede "C:\Program Files" (non "Program Files (x86)")
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
InfoBeforeFile=prima.txt
OutputDir=..\dist
OutputBaseFilename=PiumaAV-{#AppVersion}-Setup
SetupIconFile={#IconFile}
UninstallDisplayIcon={app}\setup\piuma.ico
UninstallDisplayName=PiumaAV
WizardStyle=modern
Compression=lzma2/max
SolidCompression=yes
CloseApplications=no
RestartApplications=no
SetupLogging=yes

[Languages]
Name: "it"; MessagesFile: "compiler:Languages\Italian.isl"

[Messages]
it.FinishedLabel=PiumaAV e' installato e la protezione e' attiva.%n%nLo scudo verde e' vicino all'orologio (se non lo vedi, clicca sulla freccia ^ delle icone nascoste).

[Tasks]
Name: "defender"; Description: "Rafforza anche Microsoft Defender: regole anti-ransomware e anti-exploit (facoltativo, puo' bloccare macro di Office o programmi poco comuni)"; Flags: unchecked

[InstallDelete]
; file di una versione precedente: il pacchetto viene ricopiato da zero
Type: filesandordirs; Name: "{app}\setup"

[Files]
Source: "{#PkgDir}\*"; DestDir: "{app}\setup"; Flags: recursesubdirs createallsubdirs ignoreversion
Source: "{#IconFile}"; DestDir: "{app}\setup"; DestName: "piuma.ico"; Flags: ignoreversion

[Icons]
Name: "{group}\Ripara PiumaAV (diagnosi)"; Filename: "{app}\setup\RIPARA.bat"; IconFilename: "{app}\setup\piuma.ico"
Name: "{group}\Leggimi"; Filename: "{app}\setup\README.md"
Name: "{group}\Disinstalla PiumaAV"; Filename: "{uninstallexe}"

[UninstallDelete]
Type: filesandordirs; Name: "{app}"

[Code]
var
  LogFile: String;
  InstallFailed: Boolean;

function PowerShellExe(): String;
begin
  { in modalita' 64 bit {sys} e' la System32 a 64 bit }
  Result := ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe');
end;

procedure OnPsLog(const S: String; const Error, FirstLine: Boolean);
var
  T: String;
begin
  SaveStringToFile(LogFile, S + #13#10, True);
  T := Trim(S);
  if T = '' then
    Exit;
  if Copy(T, 1, 4) = '==> ' then
  begin
    WizardForm.StatusLabel.Caption := Copy(T, 5, Length(T)) + '...';
    WizardForm.FilenameLabel.Caption := '';
  end
  else
  begin
    if Length(T) > 110 then
      T := Copy(T, 1, 107) + '...';
    WizardForm.FilenameLabel.Caption := T;
  end;
end;

function RunPsScript(const Script, Args: String): Integer;
var
  Rc: Integer;
begin
  SaveStringToFile(LogFile, #13#10 + '##### ' + Script + ' ' + Args + #13#10, True);
  if not ExecAndLogOutput(PowerShellExe(),
      '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + Script + '" ' + Args,
      ExpandConstant('{app}\setup'), SW_HIDE, ewWaitUntilTerminated, Rc, @OnPsLog) then
    Rc := -1;
  SaveStringToFile(LogFile, '##### codice di uscita: ' + IntToStr(Rc) + #13#10, True);
  Result := Rc;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Rc: Integer;
begin
  if CurStep <> ssPostInstall then
    Exit;
  LogFile := ExpandConstant('{app}\setup\installazione.log');
  DeleteFile(LogFile);
  WizardForm.ProgressGauge.Style := npbstMarquee;
  WizardForm.StatusLabel.Caption := 'Installazione di Python, ClamAV e PiumaAV (5-15 minuti)...';
  Rc := RunPsScript(ExpandConstant('{app}\setup\install\windows\install.ps1'), '');
  InstallFailed := Rc <> 0;
  if (not InstallFailed) and WizardIsTaskSelected('defender') then
  begin
    WizardForm.StatusLabel.Caption := 'Rafforzamento di Microsoft Defender...';
    if RunPsScript(ExpandConstant('{app}\setup\install\windows\harden-defender.ps1'), '') = 0 then
      SaveStringToFile(ExpandConstant('{app}\defender-rafforzato.txt'), 'harden-defender.ps1 applicato' + #13#10, False);
  end;
  WizardForm.ProgressGauge.Style := npbstNormal;
  if InstallFailed then
  begin
    if SuppressibleMsgBox('L''installazione di PiumaAV non e'' andata a buon fine.' + #13#10 + #13#10 +
        'I dettagli sono nel file:' + #13#10 + LogFile + #13#10 + #13#10 +
        'Vuoi aprirlo adesso? (Puoi copiarne il testo e mandarlo per avere aiuto.)',
        mbError, MB_YESNO, IDNO) = IDYES then
      ShellExec('', 'notepad.exe', '"' + LogFile + '"', '', SW_SHOWNORMAL, ewNoWait, Rc);
  end;
end;

procedure CurPageChanged(CurPageID: Integer);
begin
  if (CurPageID = wpFinished) and InstallFailed then
    WizardForm.FinishedLabel.Caption :=
      'L''installazione NON e'' completa: la protezione potrebbe non essere attiva.' + #13#10 + #13#10 +
      'Dettagli: ' + LogFile + #13#10 + #13#10 +
      'Puoi riavviare questo programma di installazione, oppure usare "Ripara PiumaAV" dal menu Start.';
end;

{ ------------------------------------------------------------ disinstallazione }

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Rc: Integer;
  Src, Tmp, DataDir: String;
begin
  if CurUninstallStep <> usUninstall then
    Exit;
  if FileExists(ExpandConstant('{app}\defender-rafforzato.txt')) then
    Exec(PowerShellExe(), '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' +
         ExpandConstant('{app}\setup\install\windows\harden-defender.ps1') + '" -Undo',
         '', SW_HIDE, ewWaitUntilTerminated, Rc);
  { uninstall.ps1 cancella la cartella di PiumaAV: lo si esegue da una copia temporanea }
  Src := ExpandConstant('{app}\setup\install\windows\uninstall.ps1');
  Tmp := AddBackslash(GetTempDir()) + 'PiumaAV-uninstall.ps1';
  if FileCopy(Src, Tmp, False) then
  begin
    Exec(PowerShellExe(), '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + Tmp + '"',
         GetTempDir(), SW_HIDE, ewWaitUntilTerminated, Rc);
    DeleteFile(Tmp);
  end;
  DataDir := ExpandConstant('{commonappdata}\PiumaAV');
  if DirExists(DataDir) then
    if SuppressibleMsgBox('Vuoi eliminare anche impostazioni, log e quarantena di PiumaAV?' + #13#10 +
        '(' + DataDir + ')' + #13#10 + #13#10 +
        'Scegli No se vuoi conservare i file messi in quarantena.',
        mbConfirmation, MB_YESNO or MB_DEFBUTTON2, IDNO) = IDYES then
      DelTree(DataDir, True, True, True);
end;
