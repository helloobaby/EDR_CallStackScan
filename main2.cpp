ThreadScanReport* pesieve::ThreadScanner::scanRemote()
{
	HANDLE hThread = OpenThread(
		THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | SYNCHRONIZE,
		FALSE,
		info.tid
	);
	if (!hThread) {
#ifdef _DEBUG
		std::cerr << "[-] Could not OpenThread. Error: " << GetLastError() << std::endl;
#endif
		return nullptr;
	}
#ifdef _DEBUG
	std::cout << std::dec << "---\nTid: " << info.tid << "\n";
	if (info.is_extended) {
		std::cout << " Start: " << std::hex << info.ext.start_addr << std::dec << " State: " << info.ext.state;
		if (info.ext.state == Waiting) {
			std::cout << " WaitReason: " << info.ext.wait_reason 
				<< " WaitTime: " << info.ext.wait_time;
		}
		std::cout << "\n";
		resolveAddr(info.ext.start_addr);
	}
       
#endif
       
	ThreadScanReport* my_report = new ThreadScanReport(info.tid);
#ifndef _DEBUG
	// if NOT compiled in a debug mode, make this check BEFORE scan
	if (!should_scan(info)) {
		CloseHandle(hThread); // close the opened thread
		my_report->status = SCAN_NOT_SUSPICIOUS;
		return my_report;
	}
#endif
	thread_ctx c = { 0 };
	const bool is_ok = fetchThreadCtx(processHandle, hThread, c);

	DWORD exit_code = 0;
	GetExitCodeThread(hThread, &exit_code);
	CloseHandle(hThread);

	if (!is_ok) {
		// could not fetch the thread context and information
		my_report->status = SCAN_ERROR;
		return my_report;
	}
#ifdef _DEBUG
	std::cout << " b:" << c.is64b << std::hex << " Rip: " << c.rip << " Rsp: " << c.rsp; 
	if (exit_code != STILL_ACTIVE) 
		std::cout << " ExitCode: " << exit_code;

	if (c.ret_addr != 0) {
		std::cout << std::hex << " Ret: " << c.ret_addr;
	}
	std::cout << "\n";
#endif

	if (exit_code != STILL_ACTIVE) {
		my_report->status = SCAN_NOT_SUSPICIOUS;
		return my_report;
	}
#ifdef _DEBUG
	// if compiled in a debug mode, make this check AFTER scan
	// (so that we can see first what was skipped)
	if (!should_scan(info)) {
		my_report->status = SCAN_NOT_SUSPICIOUS;
		return my_report;
	}
#endif
        if (c.is_managed) {
          my_report->status = SCAN_NOT_SUSPICIOUS;
          my_report->isDotNetModule = true;
          return my_report;
		}


        if (c.is_legit) {
          my_report->status = SCAN_NOT_SUSPICIOUS;
		} else{
          my_report->status = SCAN_SUSPICIOUS;
		}
	return my_report;
}
