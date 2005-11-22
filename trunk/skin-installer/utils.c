/*
This software is released into the public domain.  You are free to 
redistribute and modify without any restrictions with the exception of
the following:

The Zlib library is Copyright (C) 1995-2002 Jean-loup Gailly and Mark Adler.
The Unzip library is Copyright (C) 1998-2003 Gilles Vollant.
*/
#include "skin.h"

static LPCTSTR GetManifestValue(LPCTSTR manifest, LPCTSTR searchKey);
static int CheckManifestForSkin(LPCTSTR pszFile);

// EXPORT BEGIN
void LoadManifestInfo(char *buf)
{
	TCHAR* p;
	char* tmp = buf;
	int nLen = 0;
	LPTSTR pszBuf;

	if ( strlen(buf) > 3 && (UCHAR)(*tmp) == 0xEF && (UCHAR)*(tmp+1) == 0xBB && (UCHAR)*(tmp+2) == 0xBF )
		buf += 3;

	nLen = MultiByteToWideChar( CP_UTF8, 0, (LPCSTR)buf, strlen(buf) , NULL, 0 );
	pszBuf = (TCHAR*)malloc( nLen * sizeof(TCHAR) );
	MultiByteToWideChar( CP_UTF8, 0, (LPCSTR)buf, strlen(buf), pszBuf, nLen * sizeof(TCHAR) );

	if (p=(TCHAR*)GetManifestValue(pszBuf, L"type")) {
		if (!_wcsicmp(p, L"language")) {
			skinType = 1;
		}
		free(p);
	}
	if (p=(TCHAR*)GetManifestValue(pszBuf, L"name")) {
		szName = _wcsdup(p);
		free(p);
	}
	if (p=(TCHAR*)GetManifestValue(pszBuf, L"version")) {
		szVersion = _wcsdup(p);
		free(p);
	}
	if (p=(TCHAR*)GetManifestValue(pszBuf, L"author")) {
		szAuthor = _wcsdup(p);
		free(p);
	}
	if (p=(TCHAR*)GetManifestValue(pszBuf, L"updatedby")) {
		szUpdates = _wcsdup(p);
		free(p);
	}
}

int SetSkinAsDefault() {
	HKEY hkey;
	TCHAR szXMLNorm[MAX_PATH];

	if (szXML==NULL) return 0;
	wcscpy(szXMLNorm, (LPCTSTR)szName);
	wcscat(szXMLNorm, L"\\");
	wcscat(szXMLNorm, (LPCTSTR)szXML);

	if (ERROR_SUCCESS==RegOpenKeyEx(HKEY_CURRENT_USER, L"Software\\Shareaza\\Shareaza\\Skins", 0, KEY_ALL_ACCESS, &hkey)) {
		int i = 0, needsKey = 1;
		TCHAR key[256];
		DWORD keys = sizeof(key);
		DWORD dval;

		for(i=0;; i++) {
			keys = sizeof(key);
			if (RegEnumValue(hkey, i, key, &keys, NULL, NULL, NULL, NULL)!=ERROR_SUCCESS) break;
			if (!_wcsicmp((LPCTSTR)key, (LPCTSTR)szXMLNorm)) {
				needsKey = 0;
				dval = 1;
				RegSetValueEx(hkey,key,0,REG_DWORD,(LPBYTE)&dval,sizeof(DWORD));
			}
			else if (wcslen((LPCTSTR)key)) {
				if (CheckManifestForSkin(key)) {
					dval = 0;
					RegSetValueEx(hkey,key,0,REG_DWORD,(LPBYTE)&dval,sizeof(DWORD));
				}
			}
		}
		if (needsKey) {
			DWORD dval = 1;
			RegSetValueEx(hkey,szXMLNorm,0,REG_DWORD,(LPBYTE)&dval,sizeof(DWORD));
		}
		RegCloseKey(hkey);
	}
	else {
		free(szXMLNorm);
		return 0;
	}
//	free(szXMLNorm);
	return 1;
}

int MakeDirectory(LPCTSTR newdir) {
	TCHAR* buffer;
	TCHAR* p;
	int len = wcslen(newdir);

	if (len<=0) return 0;
	buffer = (TCHAR*)malloc((len+1)*sizeof(TCHAR));
	wcscpy(buffer, newdir);
	if (buffer[len-1]=='/') {
		buffer[len-1] = '\0';
	}
	if ( CreateDirectory((LPCTSTR)buffer, NULL) == TRUE ) {
		free(buffer);
		return 1;
    }
	p = buffer+1;
	while(1) {
		TCHAR hold;
		while(*p&&*p!='\\'&&*p!='/') p++;
		hold = *p;
		*p = 0;
		if (( CreateDirectory((LPCTSTR)buffer, NULL)==FALSE) && (GetLastError() != ERROR_ALREADY_EXISTS)) {
			free(buffer);
			return 0;
        }
		if (hold==0)
			break;
		*p++ = hold;
    }
	free(buffer);
	return 1;
}
// EXPORT END

static LPCTSTR GetManifestValue(LPCTSTR manifest, LPCTSTR searchKey) {
	TCHAR* p;
	LPTSTR kstart, vstart;
	int klen, vlen;
	TCHAR* key;
	TCHAR* val;
	TCHAR* info = _wcsdup(manifest);
	TCHAR* ret;

	if (p = wcsstr(info, L"/>")) {
		info += 10;
		*p = '\0';
		for (p=info;;) {
			for (;*p!='\0' && (*p==' ' || *p=='\t'); p++);
			if (*p == '\0')
				break;
			kstart = p;
			for (;*p!='\0' && *p!='=' && *p!=' ' && *p!='\t'; p++);
			klen = p-kstart;
			for (;*p!='\0' && (*p==' ' || *p=='\t'); p++);
			if (*p == '\0') break;
			if (*p != '=') continue;
			p++;
			for (;*p!='\0' && (*p==' ' || *p=='\t'); p++);
			if (*p == '\0') {
				break;
			}
			if (*p=='\'' || *p=='"') {
				p++;
				vstart = p;
				for (;*p!='\0' && *p!=*(vstart-1); p++);
				vlen = p-vstart;
				if (*p != '\0') p++;
			}
			else {
				vstart = p;
				for (;*p!='\0' && *p!=' ' && *p!='\t'; p++);
				vlen = p-vstart;
			}
			key = (TCHAR*) malloc((klen+1)*sizeof(TCHAR));
			wcsncpy(key, kstart, klen);
			key[klen] = '\0';
			val = (TCHAR*) malloc((vlen+1)*sizeof(TCHAR));
			wcsncpy(val, vstart, vlen);
			val[vlen] = '\0';
			if (klen && !_wcsicmp(key, searchKey)) {
				ret = _wcsdup(val);
				free(key);
				free(val);
				//free(info);
				return ret;
			}
			free(key);
			free(val);
		}
	}
	//free(info);
	return NULL;
}

static int CheckManifestForSkin(LPCTSTR pszFile) {
	TCHAR modDir[MAX_PATH], *tmp, *tt, *val;
	FILE * pFile;
	long lSize;
	char *buffer;
	int skin = 0, nLen = 0;
	LPTSTR pszBuf;
	char* p;
	BOOL bBOM = 0;

	GetModuleFileName( NULL, modDir, sizeof(modDir) );
	tmp = wcsrchr( modDir, L'\\');
	if (tmp) *tmp=0;
	SetCurrentDirectory(modDir);

	pFile = _wfopen( pszFile , L"rb");
	if (pFile == NULL) return 0;

	fseek(pFile , 0 , SEEK_END);
	lSize = ftell(pFile);
	rewind(pFile);

	buffer = (char*) malloc(lSize);
	p = buffer;
	if (buffer == NULL) return 0;
	fread(buffer, 1, lSize, pFile);

	if ( strlen(buffer) > 3 && (UCHAR)(*p) == 0xEF && (UCHAR)*(p+1) == 0xBB && (UCHAR)*(p+2) == 0xBF )
	{
		bBOM = TRUE;
		buffer += 3;
	}

	nLen = MultiByteToWideChar( CP_UTF8, 0, (LPCSTR)buffer, strlen(buffer) , NULL, 0 );
	pszBuf = (TCHAR*)malloc( nLen * sizeof(TCHAR) );
	MultiByteToWideChar( CP_UTF8, 0, (LPCSTR)buffer, strlen(buffer), pszBuf, nLen * sizeof(TCHAR) );
	if ( bBOM ) buffer -= 3;
	free(buffer);

	if (!(tt = wcsstr(pszBuf, L"<manifest"))) {
		fclose(pFile);
		free(pszBuf);
		return 1;
	}
	
	val = (TCHAR*)GetManifestValue(tt, L"type");
	if (!val) skin = 1;
	else {
		if (!_wcsicmp(val, L"skin")) skin = 1;
		free(val);
	}
	fclose(pFile);
	free(pszBuf);
	return skin;
}