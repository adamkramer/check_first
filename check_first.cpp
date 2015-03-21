/*  This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

	This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
 
    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 
    Created by Adam Kramer [2015] - Email: adamkramer at hotmail dot com */

#include "stdafx.h"
#include "windows.h"
#include "Wininet.h"

#pragma comment(lib, "Wininet.lib")

#define BUFSIZE 10240 // We will use a standard buffer size of 10KB
#define APIKEY "79fa30f4f738b881b4f25b7347e240a909fb3f2b9454e1dc7d168e8ee04ea4c9" // This is my VirusTotal shared API key
#define VERSION_NUMBER L"check_first v1.1"

bool submit_VT_scan(LPWSTR pFile)
{
	printf("Info: Beginning transmission of file to VirusTotal...\n");

	/* Identify size of file, so we can load it into memory */
	HANDLE hFile = CreateFile(pFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);

	DWORD dFileSize = GetFileSize(hFile, NULL);

	/* VT has a max file upload size of 32MB - check whether the file is too big */
	if (dFileSize > 32000000)
	{
		printf("Error: File is too large to be transmitted to VT (max size: 32MB)\n");
		return FALSE;
	}

	/* Convert path from wide character to non-wide character */
	char cFilePath[MAX_PATH];
	wcstombs_s(NULL, cFilePath, MAX_PATH, pFile, _TRUNCATE);

	
	/* Identify whether we have a full or local path, if full, strip down to just filename */
	char* cFilePathFinalSlash = strrchr(cFilePath, '\\');
	char cFileName[MAX_PATH];

	if (!cFilePathFinalSlash)
		strcpy_s(cFileName, cFilePath);
	else
	{
		strcpy_s(cFileName, cFilePathFinalSlash);
		cFilePathFinalSlash++;
	}


	/* Transmit to VT */
	/******************/


	/* Build HTTPS connection */
	HANDLE hInternet = InternetOpen(VERSION_NUMBER, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
	HANDLE hConnect = InternetConnect(hInternet, L"www.virustotal.com", INTERNET_DEFAULT_HTTPS_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
	HANDLE hRequest = HttpOpenRequest(hConnect, L"POST", L"/vtapi/v2/file/scan", NULL, NULL, NULL, INTERNET_FLAG_SECURE, 0);
	
	/* Build HTTP headers */
	TCHAR cHttpHeaders[] = L"Content-Type: multipart/form-data; boundary=e6922007-0bb1-456a-aaa4-d252e8e8099b\r\n\r\n";
	
	
	/* Multi-part entry for API key */
	char cHttpApiKeyHead[] = "--e6922007-0bb1-456a-aaa4-d252e8e8099b\r\n"
						   	"Content-Disposition: form-data; name=\"apikey\"\r\n\r\n"
							APIKEY
							"\r\n";

	/* Multi-part entry for FILE */
	char *cHttpFileHead = new char[strlen(cFileName) + 141];

	strcpy_s(cHttpFileHead, strlen(cFileName) + 141, "--e6922007-0bb1-456a-aaa4-d252e8e8099b\r\nContent-Disposition: form-data; name=\"file\"; filename=\"");
	strcat_s(cHttpFileHead, strlen(cFileName) + 141, cFileName);
	strcat_s(cHttpFileHead, strlen(cFileName) + 141, "\"\r\nContent-Type: application/octet-stream\r\n\r\n");

	/* Multi-part TAIL */
	char cHttpTail[] = "\r\n--e6922007-0bb1-456a-aaa4-d252e8e8099b--\r\n";

	HttpAddRequestHeaders(hRequest, cHttpHeaders, -1, HTTP_ADDREQ_FLAG_ADD | HTTP_ADDREQ_FLAG_REPLACE);

	/* Setup internet buffer */
	INTERNET_BUFFERS inetBuff;
	DWORD dBytesWritten = 0;

	memset(&inetBuff, 0, sizeof(INTERNET_BUFFERS));

	inetBuff.dwStructSize = sizeof(INTERNET_BUFFERS);
	inetBuff.dwBufferTotal = strlen(cHttpApiKeyHead) + strlen(cHttpFileHead) + dFileSize + strlen(cHttpTail);

	/* Start HTTP transfer */
	HttpSendRequestEx(hRequest, &inetBuff, NULL, HSR_INITIATE, 0);

	/* Send multi-part API, and start of FILE */
	InternetWriteFile(hRequest, (const void*)cHttpApiKeyHead, strlen(cHttpApiKeyHead), &dBytesWritten);
	InternetWriteFile(hRequest, (const void*)cHttpFileHead, strlen(cHttpFileHead), &dBytesWritten);

	/* Now send the actual file, looping through BUFSIZE chunks */
	DWORD dwRead = 0;
	BOOL bResult = FALSE;
	BYTE bFileBuffer[BUFSIZE];

	while (bResult = ReadFile(hFile, bFileBuffer, BUFSIZE, &dwRead, NULL))
		if (!dwRead)
			break;
		else
			InternetWriteFile(hRequest, (const void*)bFileBuffer, dwRead, &dBytesWritten);

	if (!bResult)
		printf("Error: Could not read file\n");

	/* Finally, send the multi-part tail */
	InternetWriteFile(hRequest, (const void*)cHttpTail, strlen(cHttpTail), &dBytesWritten);

	/* Send HTTP transmission */
	HttpEndRequest(hRequest, NULL, HSR_INITIATE, 0);

	/* Obtain HTTP status code */
	DWORD StatusCode = 0;
	DWORD StatusCodeLen = sizeof(StatusCode);
	HttpQueryInfo(hRequest, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &StatusCode, &StatusCodeLen, NULL);

	/* Error handling based on VT API status code specifications */
	if (StatusCode == 204)
	{
		printf("Error: VirusTotal only allows 4 queries per minute - please wait a minute...\n");
		return FALSE;
	}
	else if (StatusCode == 403)
	{
		printf("Error: VirusTotal API key is no longer valid! Check my github to see if there's another\n");
		return FALSE;
	}
	else if (StatusCode != 200)
	{
		printf("Error: We did not receive HTTP status 200 (OK), but rather %d\n", StatusCode);
		return FALSE;
	}

	/* Read HTTP result */
	char szBuffer[BUFSIZE] = ""; // This holds response read from InternetReadFile
	InternetReadFile(hRequest, szBuffer, BUFSIZE, &dwRead);

	/* Shut down HTTP handles */
	InternetCloseHandle(hInternet);
	InternetCloseHandle(hConnect);
	InternetCloseHandle(hRequest);

	/* Check whether the operation was a success and report to user */
	if (strstr(szBuffer, "\"response_code\": 1"))
		printf("Info: File successfully transferred to VirusTotal\n");
	else
		printf("Error: Unable to confirm that file was successfully transferred to VirusTotal\n");

	return TRUE;
}

BOOL retrieve_VT_report(char* cCompleteHash, char* szBuffer, LPDWORD dwRead)
{
	/* Build HTTP POST string */
	char frmdata[200];
	strcpy_s(frmdata, "resource=");
	strcat_s(frmdata, cCompleteHash);
	strcat_s(frmdata, "&apikey=");
	strcat_s(frmdata, APIKEY);

	/* Build HTTPS connection */
	HANDLE hInternet = InternetOpen(VERSION_NUMBER, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
	HANDLE hConnect = InternetConnect(hInternet, L"www.virustotal.com", INTERNET_DEFAULT_HTTPS_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
	HANDLE hRequest = HttpOpenRequest(hConnect, L"POST", L"/vtapi/v2/file/report", NULL, NULL, NULL, INTERNET_FLAG_SECURE, 0);

	/* Send... */
	HttpSendRequest(hRequest, NULL, NULL, frmdata, strlen(frmdata));

	/* Obtain HTTP status code */
	DWORD StatusCode = 0;
	DWORD StatusCodeLen = sizeof(StatusCode);
	HttpQueryInfo(hRequest, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &StatusCode, &StatusCodeLen, NULL);

	/* Error handling based on VT API status code specifications */
	if (StatusCode == 204)
	{
		printf("Error: VirusTotal only allows 4 queries per minute - please wait a minute...\n");
		return FALSE;
	}
	else if (StatusCode == 403)
	{
		printf("Error: VirusTotal API key is no longer valid! Check my github to see if there's another\n");
		return FALSE;
	}
	else if (StatusCode != 200)
	{
		printf("Error: We did not receive HTTP status 200 (OK), but rather %d\n", StatusCode);
		return FALSE;
	}

	/* Read HTTP result */
	InternetReadFile(hRequest, szBuffer, BUFSIZE, dwRead);

	/* Shut down HTTP handles */
	InternetCloseHandle(hInternet);
	InternetCloseHandle(hConnect);
	InternetCloseHandle(hRequest);

	return TRUE;
}


int main(int argc, char* argv[])
{

	/* Display welcome string */
	printf("check_first (v1.1) - Adam Kramer (2015)\n");

	/* Check whether an argument has been passed in, else display usage details */
	if (argc < 2)
	{
		printf("Usage: check_first.exe <file path> [Optional arguments]\n\n");
		printf("Optional: /stop-unknowns (or /stop)\nPrevents execution of files that VirusTotal has never seen\n**This is more restrictive but offers a higher degree of protection**\n\n");
		printf("Optional: /submit-unknowns (or /submit)\nSubmits the file to VirusTotal for scanning if they have never seen it before\n**Without /wait-response, this doesn't wait for response to make decision**\n\n");
		printf("Optional: /wait-response (or /wait)\nWill wait for the response to /submit-unknowns before proceeding\n**Sometimes this can take a while!  Automatically activates /submit-unknowns**\n");
		return 1;
	}

	/* Start of argument processing */
	BOOL bStopUnknowns = FALSE;
	BOOL bSubmitUnknowns = FALSE;
	BOOL bWaitResponse = FALSE;

	if (argc > 2)
	{
		for (int i = 2; i < argc; i++)
		{
			if (!strcmp(argv[i], "/stop-unknowns") || !strcmp(argv[i], "/stop"))
			{
				printf("Info: Stop unknowns mode activated\n");
				bStopUnknowns = TRUE;
			}
			else if (!strcmp(argv[i], "/submit-unknowns") || !strcmp(argv[i], "/submit"))
			{
				printf("Info: Submit unknowns mode activated\n");
				bSubmitUnknowns = TRUE;
			}
			else if (!strcmp(argv[i], "/wait-response") || !strcmp(argv[i], "/wait"))
			{
				printf("Info: Wait response mode activated\n");
				bWaitResponse = TRUE;
			}
			else
			{
				printf("Error: Unrecognised argument %s\n", argv[i]);
				printf("Usage: check_first.exe [path to file] [optional arguments]\n");
				printf("Valid arguments are:\n/stop-unknowns, /submit-unknowns and /wait-response\n");
				return 1;
			}
		}
	}

	if (bWaitResponse && !bSubmitUnknowns)
	{
		printf("Info: Auto activating /submit-unknowns as /wait-response has been selected\n");
		bSubmitUnknowns = true;
	}
	/* End of argument processing */

	/**********************************************
		STAGE 1 : OBTAIN SHA256 HASH OF FILE
	**********************************************/

	BOOL bResult = FALSE;  // Indicates successful file read
	HCRYPTPROV hCryptProv; // Handle to cryptographic provider
	HCRYPTHASH hHash;      // Handle to cryptographic hash
	const DWORD SHA256LEN = 32; // Byte length of hash
	BYTE bHashValue[SHA256LEN]; // Byte hash value
	HANDLE hFile;		   // File handle (for CreateFile)
	BYTE bFileBuffer[BUFSIZE];  // File read buffer
	DWORD dwRead = 0;	   // Holds number of bytes read from file
	CHAR cHashGenDigits[] = "0123456789abcdef"; // Used to generate human readable SHA256 string
	char cCompleteHash[SHA256LEN * 2 + 1]; // Holds human readable SHA256 string

	/* Convert argument into wide character string */
	wchar_t w[MAX_PATH];
	size_t size_of_w = sizeof(w);
	mbstowcs_s(&size_of_w, w, argv[1], MAX_PATH);
	LPWSTR pFile = w;

	/* Create handle to specified file */
	hFile = CreateFile(pFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);

	/* Error handling for file handle */
	if (INVALID_HANDLE_VALUE == hFile)
	{
		printf("Error: Could not open file\n");
		return 1;
	}

	/* Setup hashing system using CryptAPI */
	if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
	{
		printf("Error: Could not acquire context\n");
		return 1;
	}

	if (!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash))
	{
		printf("Error: Could not create hash object\n");
		return 1;
	}

	/* Read file into buffer bFileBuffer and begin hasing process */
	while (bResult = ReadFile(hFile, bFileBuffer, BUFSIZE, &dwRead, NULL))
	{
		if (!dwRead)
			break;

		if (!CryptHashData(hHash, bFileBuffer, dwRead, 0))
		{
			printf("Error: Could not hash data\n");
			CryptReleaseContext(hCryptProv, 0);
			CryptDestroyHash(hHash);
			CloseHandle(hFile);
			return 1;
		}
	}

	/* Error handling for file reading */
	if (!bResult)
	{
		printf("Error: Could not read file\n");
		CryptReleaseContext(hCryptProv, 0);
		CryptDestroyHash(hHash);
		CloseHandle(hFile);
		return 1;
	}

	/* Obtain final hash */
	if (!CryptGetHashParam(hHash, HP_HASHVAL, bHashValue, (DWORD *)&SHA256LEN, 0))
	{
		printf("Error: Could not retrieve hash\n");
	}

	/* Close down crypto and file handles */
	CryptDestroyHash(hHash);
	CryptReleaseContext(hCryptProv, 0);
	CloseHandle(hFile);

	/* Post processing of the hash to make it into the format we know & love */
	int j = 0;

	for (DWORD i = 0; i < 64; i += 2)
	{
		cCompleteHash[i] = cHashGenDigits[bHashValue[j] >> 4];
		cCompleteHash[i + 1] = cHashGenDigits[bHashValue[j] & 0xf];
		j++;
	}

	cCompleteHash[64] = '\0';

	/* Display hash to the user */
	wprintf(L"Info: %s has the SHA256 hash value of ", pFile);
	printf("%s\n", cCompleteHash);

	/**********************************************
	  STAGE 2 : TRANSMIT HASH TO VIRUSTOTAL
	 **********************************************/

	char szBuffer[BUFSIZE] = ""; // This holds response read from InternetReadFile

	if (!retrieve_VT_report(cCompleteHash, szBuffer, &dwRead))
		return 1;

	/**********************************************
	  STAGE 3 : POST PROCESSING OF VT RESULT
	  **********************************************/

	/* Action according to result from VT */

	TCHAR cVTResultsPage[MAX_PATH] = L"https://www.virustotal.com/en/file/"; // Base character array of VT API URL

	/* Check whether we're submitting unknown files and action accordingly */
	
	if (bSubmitUnknowns && strstr(szBuffer, "\"response_code\": 0"))
	{
		printf("Info: VirusTotal has never seen this hash before, submitting as requested\n");
		if (!submit_VT_scan(pFile))
			return 1;

		/* Obtain a new report after the file has been submitted */
		if (!retrieve_VT_report(cCompleteHash, szBuffer, &dwRead))
			return 1;

		/* Check whether /wait-response is active, and action accordingly */
		if (bWaitResponse)
		{
			printf("Info: Awaiting response from submitted scan as requested...\n");
			for (;;)
				if (strstr(szBuffer, "\"response_code\": 0"))
				{
					/* VT only allows 4 scans per minute, so the 20 second break is to be safe */
					printf("Info: Scan result not ready, waiting 20 seconds...\n");
					Sleep(20000);

					/* Get the latest report, to see whether it has been updated */
					if (!retrieve_VT_report(cCompleteHash, szBuffer, &dwRead))
						return 1;
				}
				else
					/* We break if the response_code is no longer 0 (i.e. it has now has the file processed) */
					break;
		}
	}

	
	
	if (strstr(szBuffer, "\"detected\": true"))
	{
		/* In this case, the response shows positive AV detections - so we will load the browser with results */
		printf("Info: There was at least one VirusTotal detection - launching results page...\n");

		/* Convert argument into wider character string */
		wchar_t x[MAX_PATH];
		size_t size_of_x = sizeof(x);
		mbstowcs_s(&size_of_x, x, cCompleteHash, MAX_PATH);
		
		/* Build VT results page URL */
		LPWSTR wCompleteHash = x;
		wcscat_s(cVTResultsPage, wCompleteHash);
		wcscat_s(cVTResultsPage, L"/analysis/");
		
		/* Open browser to the relevant VT results page for user */
		ShellExecute(NULL, L"open", cVTResultsPage, NULL, NULL, SW_SHOWNORMAL);
	} 
	else if (strstr(szBuffer, "\"response_code\": 0") && bStopUnknowns)
	{

		/* Catch unknowns when 'stop-unknowns' active */
		printf("Info: VT has not seen the hash before, file will not execute as 'stop-unknowns' parameter active\n");
		return 1;
	
	}
	else if (strstr(szBuffer, "\"detected\": false") || strstr(szBuffer, "\"response_code\": 0"))
	{
		/* Info message, letting user known VT has never seen the file before */
		/* TODO: Build in upload function (if certain argument is specified) */

		/* In this case, there is either no positive detections, or resposne code 0 (as per API specs) */
		printf("Info: No VirusTotal detections found, launching program...\n");

		/* Convert arguement into wide character string */
		wchar_t x[MAX_PATH];
		size_t size_of_x = sizeof(x);
		mbstowcs_s(&size_of_x, x, argv[1], MAX_PATH);
		pFile = x;

		/* Execute program as specified by arguement */
		ShellExecute(NULL, L"open", pFile, NULL, NULL, SW_SHOWNORMAL);

	}
	else
	{
		/* If the response didn't contain what we were expecting, throw an error */

		printf("Error: Report data not received from VirusTotal\n");
		return 1;
	}

	return 0;
}
