ScanStatus ScanProcessByStackUnwind(DWORD Pid) {
	using pesieve::util::thread_info;
	

	HANDLE hProcess = OpenProcess(
            SYNCHRONIZE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                    false, Pid);
        if (!hProcess) {
#ifdef _DEBUG
          std::cout << "OpenProcess failed   Pid : " << Pid << "\n";
#endif  // _DEBUG
          return ScanStatus::Legit;
		}

  std::vector<thread_info> threads_info;
  if (!util::fetch_threads_info(Pid, threads_info))
  {
#ifdef _DEBUG
    std::cout << "fetch_threads_info failed"<<
                  Pid << "\n ";
#endif  // _DEBUG
    return ScanStatus::Legit;
  }
  
  HMODULE hMods[1024] = {0};
  ModulesInfo ModsInfo(Pid);
  std::vector<ModuleScanReport*> moduleReports;
  size_t modules_count = 0;
  try {
	  modules_count = pesieve::util::enum_modules(
		  hProcess, hMods, sizeof(hMods), LIST_MODULES_ALL);
  }
  catch (...) {
	  return ScanStatus::Legit;
  }
  size_t counter = 0;
  for (counter = 0; counter < modules_count; counter++) {
	  const HMODULE module_base = hMods[counter];

	  ModuleData modData(hProcess, module_base, true, 0);

	  if (modData.loadOriginal()) {
		  UnreachableModuleReport* TempModsScanReport = new UnreachableModuleReport(
			  module_base, modData.original_size, modData.szModName);
		  
		  // pass .net
		  if (modData.isDotNet())
			  return ScanStatus::Legit;

		  moduleReports.push_back(std::move((ModuleScanReport*)TempModsScanReport));
	  }
	  else { // 有些情况下会失败
		  RemoteModuleData RemoteMods(hProcess, false, module_base);
		  ULONGLONG ModSize = RemoteMods.getModuleSize();
		  if (ModSize) {
			  ModsInfo.appendToUnreadableDiskModuleList((ULONGLONG)module_base, ModSize);
		  }

	  }
  }

  for (auto report : moduleReports) {
    ModsInfo.appendToModulesList(report);
  }

  ThreadScanner::InitSymbols((HANDLE)Pid);
  std::vector<thread_info>::iterator itr;
  for (itr = threads_info.begin(); itr != threads_info.end(); ++itr) {
    const thread_info& info = *itr;
    
    
    ThreadScanner scanner(hProcess, false, info, ModsInfo,
                          new peconv::ExportsMapper());
    ThreadScanReport* report = scanner.scanRemote();
    if (!report) continue;

	
	if (report->isDotNetModule) return ScanStatus::Legit;
		
	if (report->status == SCAN_SUSPICIOUS) {
      return ScanStatus::Suspicious;
	}



  }

  ThreadScanner::FreeSymbols((HANDLE)Pid);

  return ScanStatus::Legit;
}
